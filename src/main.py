import sys
import os
import asyncio
import json
import logging
from pathlib import Path
from typing import Literal

# Add src/ to Python path so tools_server can import config
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from agents import (
    Runner,
    InputGuardrailTripwireTriggered,
    MaxTurnsExceeded,
    handoff,
    RunItemStreamEvent,
    AgentUpdatedStreamEvent,
    RawResponsesStreamEvent,
)
from agents.mcp import MCPServerStdio
from agents.items import ToolCallItem
from openai.types.responses.response_output_item import McpCall
from firebase_admin import auth as firebase_auth

from config import run_config, MODEL_NAME, db
from agent import dropsync_agent, knowledge_agent
from usage_limit import admit_or_raise

import openai

_log = logging.getLogger("dropsync")

# Agent step budget per request (model turns incl. tool calls). The SDK default (10) is too
# tight for legitimate multi-tool asks (search → read → create → …); 30 gives complex
# requests room while still bounding runaway loops.
MAX_TURNS = 30
_MAX_TURNS_MESSAGE = (
    "I've reached my step limit for a single request "
    f"({MAX_TURNS} actions) before I could finish everything. "
    "Could you break this into smaller asks — one search or one change at a time? "
    "I'll take care of each right away."
)

app = FastAPI(title="DropSync Agent API")

# CORS — reads allowed origins from env (comma-separated)
# Default: localhost:3000 for dev
_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Retry-After"],
)


# ── Auth ────────────────────────────────────────────────────────

async def verify_user(authorization: str = Header(...)) -> str:
    """Verify Firebase ID token from Authorization header. Returns uid."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    id_token = authorization[7:]
    try:
        decoded = firebase_auth.verify_id_token(id_token)
        return decoded["uid"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def _build_sub_env(uid: str) -> dict:
    """Build the per-request MCP subprocess env with the Firebase-verified uid.

    SECURITY INVARIANTS — read before editing this function:
    1. MUST return a NEW dict via {**os.environ, ...}. NEVER write to
       os.environ (e.g. `os.environ[...] = uid`) — os.environ is shared across
       all concurrent requests in one uvicorn worker, so mutating it leaks
       user A's uid into user B's request. The dict-spread is load-bearing.
    2. DROPSYNC_VERIFIED_UID is the SOLE trust source for caller identity in
       tools_server.py. The model cannot read or override os.environ (no tool
       exposes it) and user_id is no longer a tool parameter.
    3. The MCP subprocess MUST be spawned fresh per /chat (MCPServerStdio +
       connect/cleanup below). NEVER pool/reuse subprocesses across requests —
       a stale env var serves the first user's uid to later users (silent
       impersonation that _verified_uid()'s fail-closed check does NOT catch,
       because the var is present-but-wrong, not missing).
    """
    assert isinstance(uid, str) and uid, "uid must be a non-empty string"
    return {**os.environ, "DROPSYNC_VERIFIED_UID": uid}


def _new_request_agent(user_id: str):
    """Build the per-request MCP server + cloned agent pair shared by /chat and /chat/stream.

    SECURITY (CRITICAL — race fix): clone the agents PER REQUEST. Never mutate the shared
    module-level dropsync_agent.mcp_servers — concurrent requests race on that attribute
    (await server.connect() yields to the event loop, letting a second request overwrite
    dropsync_agent.mcp_servers before Runner.run reads it, which would run request A's agent
    against request B's server/subprocess and serve B's DROPSYNC_VERIFIED_UID to A — full
    cross-user data leak). Each request gets its own private agent+server pair via clone();
    the shared dropsync_agent / knowledge_agent are never touched.

    Rewires handoffs between the per-request clones so the dropsync <-> knowledge handoff
    chain stays intact and never targets a shared module-level agent. Groq needs the relaxed
    schema (non-OpenAI providers reject the SDK's strict handoff schema — see agent.py:309-316).
    """
    tools_server_path = str(Path(__file__).parent / "tools_server.py")

    # Build per-request subprocess env carrying the Firebase-verified uid on a
    # channel the model cannot read or override (see _build_sub_env invariants).
    _sub_env = _build_sub_env(user_id)

    server = MCPServerStdio(
        params={
            "command": sys.executable,
            "args": [tools_server_path],
            "env": _sub_env,
        },
        client_session_timeout_seconds=60,
    )

    request_dropsync = dropsync_agent.clone(mcp_servers=[server])
    request_knowledge = knowledge_agent.clone()

    _req_kh = handoff(request_knowledge)
    _req_kh.input_json_schema = {"type": "object", "properties": {}}
    _req_kh.strict_json_schema = False
    _req_dh = handoff(request_dropsync)
    _req_dh.input_json_schema = {"type": "object", "properties": {}}
    _req_dh.strict_json_schema = False
    request_dropsync.handoffs = [_req_kh]
    request_knowledge.handoffs = [_req_dh]

    return server, request_dropsync


def _guardrail_message(e: Exception) -> str:
    """Canned safe reply for a tripped input guardrail, shared by /chat and /chat/stream.

    The guardrail carries its verdict (incl. category) in output_info. Default to the
    injection message if the category can't be read.
    """
    category = None
    try:
        category = (e.guardrail_result.output.output_info or {}).get("category")
    except Exception:
        category = None
    if category == "password":
        return (
            "I can't open the contents of your password drops from chat — for security, "
            "those stay private to the DropSync app. Open the app to view or manage them. "
            "(I can still tell you how many you have if you ask for your storage stats.)"
        )
    # injection — or category missing/unreadable/unknown — single safe message
    return (
        "I can't follow instructions that try to override my rules or safety settings. "
        "If you're trying to get something done with your drops, just tell me plainly "
        "what you need and I'll help!"
    )


def _classify_provider_error(e: Exception) -> tuple[str, str]:
    """Map a mid-run exception to a (kind, user-safe message) pair.

    kinds: "rate_limited" | "busy" | "unknown".
    - rate_limited / busy are TRANSIENT provider-side failures (Gemini free-tier rate
      limits, overload, timeouts): the frontend shows a transient notice and saves
      NOTHING into the conversation (the string must not be replayed to the model as
      history on later sends).
    - unknown keeps the saved error-turn behavior so genuine failures leave a trace.
    The real cause is logged server-side; str(e) never reaches the browser.
    """
    status = getattr(e, "status_code", None)
    if isinstance(e, openai.RateLimitError) or status == 429:
        return (
            "rate_limited",
            "The AI service is rate-limited right now — please wait a minute and try again.",
        )
    if (
        isinstance(e, (openai.APITimeoutError, openai.APIConnectionError))
        or status in (500, 502, 503, 504)
    ):
        return (
            "busy",
            "The AI service is busy right now — please wait a moment and try again.",
        )
    return (
        "unknown",
        "Something went wrong while processing your request. Please try again.",
    )


def _preview_from_result(result) -> tuple[str | None, str | None]:
    """Post-run scan shared by /chat and /chat/stream: find the preview_drop tool call and
    resolve its workspaceId from Firestore. Returns (previewDropId, previewWorkspaceId)."""
    preview_drop_id = None
    for item in result.new_items:
        if hasattr(item, 'raw_item') and item.raw_item:
            call = item.raw_item
            # Check name attribute on any tool call (MCP tools show as ResponseFunctionToolCall)
            call_name = getattr(call, 'name', None)
            if call_name == "preview_drop":
                args_raw = getattr(call, 'arguments', '{}')
                try:
                    args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                except Exception:
                    args = {}
                preview_drop_id = args.get("drop_id")
                break

    # Get workspace_id from Firestore if we have a drop_id
    preview_ws_id = None
    if preview_drop_id:
        doc = db.collection("drops").document(preview_drop_id).get()
        if doc.exists:
            ws_id = doc.to_dict().get("workspaceId")
            preview_ws_id = ws_id if ws_id else None
    return preview_drop_id, preview_ws_id


# ── Models ──────────────────────────────────────────────────────

class HistoryMessage(BaseModel):
    # A client cannot inject a "system" role message — only user/assistant
    # turns are allowed. role: "system" is rejected with HTTP 422 here, at the
    # request boundary, before the conversation ever reaches the model.
    role: Literal["user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[HistoryMessage] = []


class ChatResponse(BaseModel):
    response: str
    previewDropId: str | None = None
    previewWorkspaceId: str | None = None


# ── Endpoints ───────────────────────────────────────────────────

@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, user_id: str = Depends(verify_user)):
    """Run the DropSync agent with MCP tools and conversation history."""
    # Per-user agent-message quota gate (trusted = unlimited; non-trusted = 5/hr + 25/day,
    # UTC). MUST stay the first statement and OUTSIDE the try: below: on a limit hit it
    # raises HTTPException(429) with Retry-After, which must propagate as 429 — NOT be
    # swallowed by the catch-all `except Exception` (~L212) that would rewrite it to 500.
    # No MCP subprocess / Runner.run / model call is spawned when this blocks.
    await admit_or_raise(user_id)
    # Build conversation: system context + history + new message
    conversation = []

    # Add previous messages
    for msg in req.history:
        conversation.append({"role": msg.role, "content": msg.content})

    # Add new message (caller identity is NOT pasted into the prompt — it travels
    # out-of-band via DROPSYNC_VERIFIED_UID in the per-request subprocess env).
    conversation.append({"role": "user", "content": req.message})

    server, request_dropsync = _new_request_agent(user_id)

    try:
        await server.connect()
        result = await Runner.run(
            request_dropsync,
            conversation,
            run_config=run_config,
            max_turns=MAX_TURNS,
        )
        response = result.final_output

        # Inspect tool call history for preview_drop calls + resolve the workspace
        preview_drop_id, preview_ws_id = _preview_from_result(result)

        return ChatResponse(
            response=response,
            previewDropId=preview_drop_id,
            previewWorkspaceId=preview_ws_id,
        )

    except InputGuardrailTripwireTriggered as e:
        return ChatResponse(response=_guardrail_message(e))

    except MaxTurnsExceeded:
        # Step budget exhausted — an assistant-voice explanation, not an error turn.
        return ChatResponse(response=_MAX_TURNS_MESSAGE)

    except Exception as e:
        # Transient provider failures (rate limit / busy) keep their 4xx/5xx semantics so
        # the frontend shows a transient notice instead of saving an error turn — same
        # contract as /chat/stream's in-stream kinds.
        _log.exception("chat: run failed")
        kind, message = _classify_provider_error(e)
        if kind == "rate_limited":
            raise HTTPException(status_code=429, detail=message)
        if kind == "busy":
            raise HTTPException(status_code=503, detail=message)
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        await server.cleanup()


@app.post("/chat/stream")
async def chat_stream(req: ChatRequest, user_id: str = Depends(verify_user)):
    """Streaming variant of /chat: same auth, quota gate, agent setup, and final payload —
    but the response is a text/event-stream that reports what the agent is doing while it
    works. Consumed by src/lib/agentActivity.ts in the frontend.

    Wire contract:
      event: activity  data: {"phase": "generating"}                       — model turn / handoff
      event: activity  data: {"phase": "tool", "tool": "search_drops"}     — tool committed, about to run
      event: activity  data: {"phase": "tool_done"}                        — tool finished
      event: delta     data: {"text": "..."}                               — token-level text of the answer, as the model writes it
      event: delta_reset (empty)                                           — drop streamed text (model moved on to a tool after talking)
      event: final     data: {"response", "previewDropId", "previewWorkspaceId"}  — terminal; same fields as ChatResponse
      event: error     data: {"kind", "message"}                           — terminal; kind "rate_limited"/"busy" = transient
                                                                          (client shows a notice, saves nothing), "unknown"
                                                                          = saved error turn (SSE 200 already sent)
      ": keepalive" comment frames during silent gaps (ignored by SSE parsers)

    Maintenance notes (openai-agents 0.13.2 — re-verify on any SDK upgrade):
      - RunItemStreamEvent names used: tool_called / tool_output / message_output_created.
        MCP tool names arrive UN-PREFIXED (agents/mcp/util.py), so they match tools_server.py
        function names directly.
      - Guardrail + model exceptions are RE-RAISED at the END of the stream_events()
        iteration (RunResultStreaming._stored_exception) — caught around the async-for,
        after the SSE 200 headers are already committed.
      - Client disconnect (Stop button / panel close): Starlette cancels this generator;
        the finally block cancels the run and cleans the MCP subprocess inside a shielded
        task so the cancellation of THIS task can't cut cleanup short.
      - NEVER add GZip/compression middleware to this app — it buffers text/event-stream.
    """
    # Per-user quota gate. MUST stay the first statement so a 429 + Retry-After goes out as
    # a normal JSON error BEFORE the stream starts (headers still mutable), exactly like
    # /chat. No MCP subprocess / model call is spawned when this blocks.
    await admit_or_raise(user_id)

    conversation = []
    for msg in req.history:
        conversation.append({"role": msg.role, "content": msg.content})
    conversation.append({"role": "user", "content": req.message})

    server, request_dropsync = _new_request_agent(user_id)
    await server.connect()

    # Sync factory: starts the run; events are consumed from result.stream_events() below.
    result = Runner.run_streamed(
        request_dropsync,
        conversation,
        run_config=run_config,
        max_turns=MAX_TURNS,
    )

    def _sse(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    async def event_stream():
        last_activity: tuple | None = None  # (phase, tool) — emit only on CHANGE, not per event

        def activity_frame(payload: dict) -> str | None:
            nonlocal last_activity
            key = (payload.get("phase"), payload.get("tool"))
            if key == last_activity:
                return None
            last_activity = key
            return _sse("activity", payload)

        # Declared before try: the finally block retires it, and a client disconnect at the
        # very first yield must not hit an unbound name.
        next_event: asyncio.Task | None = None
        # True only when the generator was cancelled (client disconnect). result.cancel()
        # must fire on THAT path only — cancelling an already-finished run (normal final,
        # guardrail, MaxTurnsExceeded, error) reaches into the response machinery and
        # splashes a bogus "Exception in ASGI application" into the log.
        client_gone = False
        try:
            # Immediate "generating" so the client shows a label from the first moment
            # (the client translates phases; the backend only reports them).
            first = activity_frame({"phase": "generating"})
            if first:
                yield first

            events = result.stream_events().__aiter__()
            keepalive_streak = 0
            streamed_text = False  # any delta sent since the last reset
            while True:
                if next_event is None:
                    next_event = asyncio.create_task(events.__anext__())
                done, _pending = await asyncio.wait({next_event}, timeout=15.0)
                if not done:
                    # Silent gap (e.g. a long-running tool — the MCP timeout is 60s): emit an
                    # SSE comment frame so proxies don't idle out the connection. A long
                    # streak means something hung: bail instead of keepalive-ing forever.
                    keepalive_streak += 1
                    if keepalive_streak > 12:  # ~3 minutes with no event at all
                        yield _sse("error", {"kind": "busy", "message": "The assistant took too long. Please try again."})
                        return
                    yield ": keepalive\n\n"
                    continue
                keepalive_streak = 0
                try:
                    event = next_event.result()
                except StopAsyncIteration:
                    break
                next_event = None

                frame = None
                if isinstance(event, RunItemStreamEvent):
                    if event.name in ("tool_called", "handoff_requested", "handoff_occured") and streamed_text:
                        # The model emitted text and THEN moved on to a tool/handoff — that
                        # text was thinking-out-loud, not the answer. Tell the client to
                        # drop it so it never mixes into the real reply.
                        streamed_text = False
                        yield _sse("delta_reset", {})
                    if event.name == "tool_called":
                        # The tool NAME is available the moment the model commits to the
                        # call, BEFORE the tool executes — the "doing RIGHT NOW" signal.
                        tool_name = getattr(event.item.raw_item, "name", None) or "tool"
                        frame = activity_frame({"phase": "tool", "tool": tool_name})
                    elif event.name == "tool_output":
                        frame = activity_frame({"phase": "tool_done"})
                    elif event.name == "message_output_created":
                        frame = activity_frame({"phase": "generating"})
                elif isinstance(event, AgentUpdatedStreamEvent):
                    # dropsync <-> knowledge handoff — a model turn either way
                    frame = activity_frame({"phase": "generating"})
                elif isinstance(event, RawResponsesStreamEvent):
                    # ONLY answer text. The SDK also surfaces tool-call ARGUMENT deltas and
                    # reasoning deltas — they carry a .delta string too, but streaming them
                    # would type raw tool JSON into the chat bubble before the reset wipes
                    # it. Gate on the event TYPE, not the presence of .delta.
                    if getattr(event.data, "type", None) == "response.output_text.delta":
                        delta = getattr(event.data, "delta", None)
                        if isinstance(delta, str) and delta:
                            streamed_text = True
                            yield _sse("delta", {"text": delta})
                if frame:
                    yield frame

            # Iteration finished without exception → run complete; reuse /chat's post-run logic.
            # to_thread: the firebase-admin get inside is a blocking RPC — keep it off the
            # event loop so a slow Firestore read can't stall other concurrent streams.
            preview_drop_id, preview_ws_id = await asyncio.to_thread(_preview_from_result, result)
            yield _sse("final", {
                "response": result.final_output,
                "previewDropId": preview_drop_id,
                "previewWorkspaceId": preview_ws_id,
            })

        except InputGuardrailTripwireTriggered as e:
            yield _sse("final", {
                "response": _guardrail_message(e),
                "previewDropId": None,
                "previewWorkspaceId": None,
            })

        except MaxTurnsExceeded:
            # Step budget exhausted — an assistant-voice explanation delivered as a normal
            # final reply, not an in-stream error.
            yield _sse("final", {
                "response": _MAX_TURNS_MESSAGE,
                "previewDropId": None,
                "previewWorkspaceId": None,
            })

        except asyncio.CancelledError:
            client_gone = True
            raise  # client disconnected — the finally block does the cleanup

        except Exception as e:
            # The SSE 200 is already committed, so surface a safe in-stream error instead
            # of a 500. Rate limits / provider overload get their own kind so the client
            # shows a transient notice instead of saving an error turn. Never forward
            # str(e) (provider/model internals) to the browser — log it instead.
            _log.exception("chat/stream: run failed")
            kind, message = _classify_provider_error(e)
            yield _sse("error", {"kind": kind, "message": message})

        finally:
            # Retire the pending __anext__ task so a mid-stream generator exit (client
            # disconnect) never leaves it dangling; consume any stored exception so asyncio
            # doesn't log "exception was never retrieved".
            if next_event is not None:
                if not next_event.done():
                    next_event.cancel()
                else:
                    try:
                        next_event.exception()
                    except (asyncio.CancelledError, StopAsyncIteration, Exception):
                        pass

            async def _teardown() -> None:
                if client_gone and not result.is_complete:
                    try:
                        await result.cancel("immediate")
                    except Exception:
                        pass
                await server.cleanup()

            # Shielded: when the client disconnects, THIS generator is being cancelled at the
            # same moment — the shield lets the run-cancel + subprocess cleanup finish anyway.
            try:
                await asyncio.shield(_teardown())
            except Exception:
                pass

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # nginx-style proxies: do not buffer this stream
        },
    )


@app.get("/health")
async def health():
    return {"status": "ok", "model": MODEL_NAME}


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
