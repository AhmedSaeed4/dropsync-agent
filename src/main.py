import sys
import os
import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
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


class RunStartRequest(ChatRequest):
    # Idempotency key minted by the client per SEND: a START that failed at the
    # network layer is retried with the SAME value and must re-attach to the
    # same run, never start a second one (double-create risk on flaky networks).
    client_request_id: str


class RunStartResponse(BaseModel):
    run_id: str
    status: str


class RunCancelResponse(BaseModel):
    status: str
    # Stop-memory: what the run had accomplished when it was stopped. Present ONLY on
    # the response whose call actually performed the cancel — a second (idempotent)
    # cancel returns no summary, so exactly one client can ever receive it and there
    # is exactly one writer of the saved stop turn. Additive: old clients ignore it.
    summary: str | None = None


# ── Resumable run registry ──────────────────────────────────────
# The agent run is decoupled from the SSE connection: it executes as a detached
# asyncio task and everything it would have streamed is appended to an in-memory
# log of rendered SSE frames. A viewer (GET /chat/runs/{id}/stream) replays the
# log from frame 0 and then follows live, so a client network hiccup just means
# re-attaching — the finished answer is never lost, and asking twice with the
# same client_request_id can never start two runs.
#
# SINGLE-PROCESS ASSUMPTION: the HF Space runs `uvicorn src.main:app` with no
# --workers (see Dockerfile CMD), so a module-level dict IS the registry. If
# this app ever runs with multiple workers, runs split across processes and
# attach would 404 — move the registry to shared storage first.

_RUN_TTL_SECONDS = 600.0  # finished runs stay replayable ~10 min, then lazily evicted
_MAX_RUNS = 200           # hard cap so the registry can't grow without bound


@dataclass
class _ChatRun:
    run_id: str
    user_id: str
    client_request_id: str
    status: str = "running"  # running | completed | error | cancelled
    # Ordered RENDERED SSE frames (terminal included): the log IS the stream.
    # Storing final strings keeps replay a plain yield and the memory bounded
    # to what was actually sent.
    frames: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.monotonic)
    finished_at: float | None = None
    cancel_requested: bool = False
    result: object | None = None      # RunResultStreaming — the genuine-cancel handle
    task: asyncio.Task | None = None  # fallback cancel handle (pre-stream window)
    viewers: int = 0                  # attached follow generators (blocks TTL eviction)
    cancel_summary: str | None = None  # stop-memory: what the run had done when stopped


_runs: dict[str, _ChatRun] = {}
_runs_by_key: dict[tuple[str, str], str] = {}  # (user_id, client_request_id) -> run_id
_registry_lock = asyncio.Lock()


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _sweep_runs() -> None:
    """Evict reclaimable runs. No awaits inside → atomic on the single event loop.

    Running runs are NEVER evicted (they self-terminate: the runner's ~3-min
    keepalive bail, the 60s MCP timeout, MAX_TURNS=30). Runs with a live viewer
    are kept so a TTL expiry mid-view doesn't yank the log out from under an
    open stream — only a RE-attach after eviction 404s.
    """
    now = time.monotonic()
    for run_id in list(_runs):
        run = _runs[run_id]
        if (
            run.finished_at is not None
            and run.viewers == 0
            and (now - run.finished_at) > _RUN_TTL_SECONDS
        ):
            _runs.pop(run_id, None)
            _runs_by_key.pop((run.user_id, run.client_request_id), None)
    # Hard cap: drop oldest-finished-first when over budget.
    if len(_runs) > _MAX_RUNS:
        reclaimable = sorted(
            (r for r in _runs.values() if r.finished_at is not None and r.viewers == 0),
            key=lambda r: r.finished_at or 0.0,
        )
        for run in reclaimable[: len(_runs) - _MAX_RUNS]:
            _runs.pop(run.run_id, None)
            _runs_by_key.pop((run.user_id, run.client_request_id), None)


def _finish_run(run: _ChatRun, status: str, terminal_frame: str) -> None:
    """Land a run's terminal state. DOUBLE-FINAL GUARD: the first caller wins and
    every later attempt (runner belt-and-braces, cancel endpoint, legacy wrapper)
    is a no-op — a cancel racing completion can never produce two terminals.
    The terminal frame is appended BEFORE the status flips, so a viewer polling
    both can never observe a terminal status whose frame it cannot yet read."""
    if run.finished_at is not None:
        return
    run.frames.append(terminal_frame)
    run.finished_at = time.monotonic()
    run.status = status


def _get_owned_run(run_id: str, user_id: str) -> _ChatRun:
    """Fetch a run for its owner. Unknown AND not-yours both 404 — never confirm
    that another user's run exists."""
    run = _runs.get(run_id)
    if run is None or run.user_id != user_id:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


async def _start_or_get_run(
    user_id: str, message: str, history: list[HistoryMessage], client_request_id: str
) -> _ChatRun:
    """Create (or idempotently return) a chat run, spawning its detached runner.

    Ordering matters: the idempotency lookup runs BEFORE the quota gate so a
    retried START (same client_request_id — e.g. its first response was lost to
    a network hiccup) returns the existing run WITHOUT a second charge against
    the per-hour limit. For every genuinely NEW run, admit_or_raise still runs
    before any registry insert, MCP subprocess, or model call — its 429 +
    Retry-After escapes as a normal JSON error before any SSE headers, exactly
    like /chat.
    """
    key = (user_id, client_request_id)
    async with _registry_lock:
        _sweep_runs()
        existing_id = _runs_by_key.get(key)
        if existing_id and existing_id in _runs:
            return _runs[existing_id]

    await admit_or_raise(user_id)

    async with _registry_lock:
        _sweep_runs()
        existing_id = _runs_by_key.get(key)
        if existing_id and existing_id in _runs:
            # A twin POST won the race while we awaited the quota gate.
            return _runs[existing_id]
        run = _ChatRun(
            run_id=secrets.token_urlsafe(24),
            user_id=user_id,
            client_request_id=client_request_id,
        )
        run.task = asyncio.create_task(_execute_chat_run(run, user_id, message, history))
        _runs[run.run_id] = run
        _runs_by_key[key] = run.run_id
        return run


# ── Stop-memory (what had the run done when the user stopped it) ──────────
# The next message's history must tell the model the previous run was stopped and
# what ACTUALLY happened. These tables only ever name tools from tools_server.py;
# unknown tool names (handoffs surface as "transfer_to_…" calls) are skipped so no
# SDK-internal name ever reaches the user or the model. When adding a tool to
# tools_server.py, add it to these tables in the same PR — a missing entry silently
# under-reports (never mis-reports).

# A mutating call only counts as DONE when its output starts with the exact success
# line our own tool prints — the model can call delete_drop and get "Access denied"
# back, and claiming a deletion that failed would be fabrication.
_STOP_SUCCESS_PREFIXES = {
    "delete_drop": "Deleted drop '",
    "create_drop": "Created drop '",
    "update_drop": "Updated drop ",
    "move_drop": "Moved drop '",
    "copy_drop": "Copied drop '",
    "create_workspace": "Created workspace '",
    "join_workspace": "Joined workspace '",
    "delete_category": "Deleted category '",
}
_STOP_MUTATING_VERBS = {  # tool -> past-tense verb for the summary line
    "delete_drop": "Deleted",
    "create_drop": "Created",
    "update_drop": "Updated",
    "move_drop": "Moved",
    "copy_drop": "Copied",
    "create_workspace": "Created (workspace)",
    "join_workspace": "Joined (workspace)",
    "delete_category": "Deleted (category)",
}
_STOP_READ_ONLY_LABELS = {  # tools that change nothing — reported as counts only
    "search_drops": "searched your drops",
    "list_drops": "listed your drops",
    "get_drop": "looked up a drop",
    "preview_drop": "opened a drop in the app",
    "list_workspaces": "listed your workspaces",
    "list_categories": "listed your categories",
    "get_storage_stats": "checked your storage stats",
}
_STOP_TOOL_PHRASES = {  # tool -> human phrase: raw SDK tool names must NEVER reach the user
    "delete_drop": "drop deletion",
    "create_drop": "drop creation",
    "update_drop": "drop update",
    "move_drop": "drop move",
    "copy_drop": "drop copy",
    "create_workspace": "workspace creation",
    "join_workspace": "workspace join",
    "delete_category": "category deletion",
    "search_drops": "drop search",
    "list_drops": "drop listing",
    "get_drop": "drop lookup",
    "preview_drop": "drop preview",
    "list_workspaces": "workspace listing",
    "list_categories": "category listing",
    "get_storage_stats": "storage stats check",
}
_MAX_STOP_NAMES = 6  # cap per action line — keeps the turn compact for UI and history


def _stop_call_id(raw) -> str | None:
    """Read a tool item's call_id, dict-aware: the SDK's output items carry a PLAIN
    DICT raw_item ({"call_id":…, "output":…, "type":"function_call_output"}) while
    call items carry pydantic objects — getattr alone silently misses the dict
    shape, which once unpaired every output from its call (all actions read as
    "unconfirmed"). Never assume one shape."""
    if isinstance(raw, dict):
        cid = raw.get("call_id")
        return cid if isinstance(cid, str) else None
    cid = getattr(raw, "call_id", None)
    return cid if isinstance(cid, str) else None


def _stop_output_text(output_item) -> str | None:
    """Best-effort plain-text view of one completed tool call's output.

    The exact shape differs across the MCP → FunctionTool paths in openai-agents
    0.13.2: item.output is a {"type":"text","text":…} dict (MCP single-text) or a
    plain str, and raw_item is a PLAIN DICT whose "output" is a stringified copy.
    Take whichever candidate yields a string and otherwise return None — the caller
    then degrades to an "unconfirmed" phrasing instead of guessing. Never returns
    raw dicts: the summary is user-visible AND replayed to the model as history.
    """
    raw = getattr(output_item, "raw_item", None)
    raw_out = raw.get("output") if isinstance(raw, dict) else getattr(raw, "output", None)
    for candidate in (getattr(output_item, "output", None), raw_out):
        if isinstance(candidate, str):
            return candidate
        if isinstance(candidate, dict):
            text = candidate.get("text")
            if isinstance(text, str):
                return text
    return None


def _stop_success_label(tool: str, output: str, args: dict) -> str:
    """Short label for a VERIFIED tool success. Prefers the name our own tool
    printed inside single quotes (reading our own output, never guessing), then
    the call's arguments, then a bare id — the honesty ladder. NEVER fabricates."""
    if tool != "update_drop" and "'" in output:
        name = output.split("'", 1)[1].split("'", 1)[0].strip()
        if name:
            return f'"{name[:80]}"'
    # update_drop prints the drop_id, not a name — prefer an explicit new name
    # from the arguments when the model passed one.
    if tool == "update_drop":
        name = args.get("name")
        if isinstance(name, str) and name.strip():
            return f'"{name.strip()[:80]}"'
    for key in ("drop_id", "category_id", "workspace_id"):
        val = args.get(key)
        if isinstance(val, str) and val:
            return f"{key.replace('_', ' ')} {val}"
    return "an item"


def _summarize_stopped_run(run: "_ChatRun") -> str:
    """Build the Stop-memory summary from data already in memory — zero model
    calls, zero I/O, zero quota. Must stay fully synchronous.

    SOURCES (verified against openai-agents 0.13.2, run_internal/run_loop.py:941):
      - run.result.new_items: extended only at END of a turn, so every tool call in
        it already executed; its paired output item lets us verify success and pull
        real drop names from our own tool success lines. Never derive the in-flight
        state from here — the in-flight turn's items are missing by design.
      - run.frames: the live activity log; if the LAST activity phase is "tool", a
        call was in flight at stop time.
    HONESTY: a call counts as done only when its output matches a known success
    prefix; everything else is "unconfirmed" or "may have been mid-way". We never
    claim an action whose success we couldn't read, and never include raw JSON,
    ids beyond what a tool argument carried, or any exception text.
    """
    calls: dict[str, dict] = {}
    order: list[str] = []
    outputs: dict[str, str | None] = {}
    result = run.result
    if result is not None:
        for item in getattr(result, "new_items", None) or []:
            raw = getattr(item, "raw_item", None)
            if raw is None:
                continue
            call_id = _stop_call_id(raw)
            name = getattr(raw, "name", None)
            if isinstance(name, str) and name:
                if name.startswith("transfer_to_") or call_id is None or call_id in calls:
                    continue  # handoff call (not a data tool) or duplicate call item
                args_raw = getattr(raw, "arguments", "{}")
                try:
                    args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                except Exception:
                    args = {}
                if not isinstance(args, dict):
                    args = {}
                calls[call_id] = {"tool": name, "args": args}
                order.append(call_id)
            elif call_id is not None and call_id in calls:
                outputs[call_id] = _stop_output_text(item)

    verified: dict[str, list[str]] = {}
    unconfirmed: dict[str, int] = {}
    read_only: dict[str, int] = {}
    for cid in order:
        tool = calls[cid]["tool"]
        out = outputs.get(cid)
        prefix = _STOP_SUCCESS_PREFIXES.get(tool)
        if prefix is not None and out is not None and out.startswith(prefix):
            verified.setdefault(_STOP_MUTATING_VERBS[tool], []).append(
                _stop_success_label(tool, out, calls[cid]["args"])
            )
        elif tool in _STOP_READ_ONLY_LABELS:
            read_only[tool] = read_only.get(tool, 0) + 1
        elif prefix is not None:
            unconfirmed[tool] = unconfirmed.get(tool, 0) + 1
        # unknown future tool names are omitted entirely (see tables' comment)

    in_flight_tool = None
    for frame in run.frames:
        if not frame.startswith("event: activity\n"):
            continue
        for line in frame.split("\n"):
            if not line.startswith("data:"):
                continue
            try:
                data = json.loads(line[5:].strip())
            except Exception:
                continue
            phase = data.get("phase")
            if phase == "tool" and isinstance(data.get("tool"), str):
                in_flight_tool = data["tool"]
            elif phase in ("tool_done", "generating"):
                in_flight_tool = None

    if not verified and not unconfirmed and not read_only and in_flight_tool is None:
        return ("I was stopped before I could start working on this request — "
                "nothing was searched, created, changed, or deleted.")

    lines = ["I was stopped partway through your request. Here's what I had already done:"]
    for verb, labels in verified.items():
        shown = ", ".join(labels[:_MAX_STOP_NAMES])
        extra = len(labels) - _MAX_STOP_NAMES
        suffix = f" (+{extra} more)" if extra > 0 else ""
        lines.append(f"- {verb} {len(labels)}: {shown}{suffix}")
    for tool, count in unconfirmed.items():
        # Phrase, never the raw tool name — unconfirmed only holds prefix-table tools.
        phrase = _STOP_TOOL_PHRASES[tool]
        if count > 1:
            plural_phrase = phrase[:-1] + "ies" if phrase.endswith("y") else phrase + "s"
            lines.append(f"- Also attempted {count} {plural_phrase} whose results I couldn't confirm.")
        else:
            lines.append(f"- Also attempted {count} {phrase} whose result I couldn't confirm.")
    for tool, count in read_only.items():
        times = f" ({count} times)" if count > 1 else ""
        lines.append(f"- Also {_STOP_READ_ONLY_LABELS[tool]}{times}.")
    if in_flight_tool:
        # "may": frames can be a fraction of a second ahead of new_items, so this
        # call either just started or just finished — we genuinely don't know which.
        phrase = _STOP_TOOL_PHRASES.get(in_flight_tool, "tool step")
        lines.append(f"I may have been in the middle of another {phrase} when "
                     "stopped — if so, it may or may not have completed, so please double-check.")
    lines.append("Anything not listed above was not done.")
    return "\n".join(lines)


def _genuinely_cancel_run(run: _ChatRun) -> None:
    """Stop a running run for real (Stop-button semantics — saves model quota).

    Preferred handle is the SDK's result.cancel (a SYNC method in
    openai-agents 0.13.2 — never await it), falling back to cancelling the
    runner task in the brief pre-stream window. Always lands the terminal via
    _finish_run (idempotent): this covers the corner where the task is
    cancelled before its coroutine ever starts, which would otherwise leave
    viewers hanging with no terminal at all."""
    if run.status != "running":
        return
    run.cancel_requested = True
    # Snapshot what the run had actually accomplished BEFORE any teardown. This
    # function is fully synchronous (no awaits), so the runner task cannot
    # interleave on the single event loop — the snapshot is atomic. Wrapped so a
    # summary bug can never break the cancel itself (the terminal MUST land).
    try:
        run.cancel_summary = _summarize_stopped_run(run)
    except Exception:
        _log.exception("chat run: cancel summary failed")
        run.cancel_summary = None
    cancelled_frame = _sse("error", {"kind": "cancelled", "message": "Stopped."})
    try:
        if run.result is not None and not run.result.is_complete:
            run.result.cancel("immediate")
            _finish_run(run, "cancelled", cancelled_frame)
            return
    except Exception:
        pass
    if run.task is not None and not run.task.done():
        run.task.cancel()
    _finish_run(run, "cancelled", cancelled_frame)


# ── Run execution ───────────────────────────────────────────────


async def _execute_chat_run(
    run: _ChatRun, user_id: str, message: str, history: list[HistoryMessage]
) -> None:
    """Detached runner — the old /chat/stream body with every `yield` turned into
    a frames.append. It belongs to the run, not to any connection: a viewer
    disconnect never cancels it (only _genuinely_cancel_run does), so the work
    survives a phone network hiccup and a re-attaching viewer replays + follows.

    Maintenance notes (openai-agents 0.13.2 — re-verify on any SDK upgrade):
      - RunItemStreamEvent names used: tool_called / tool_output / message_output_created.
        MCP tool names arrive UN-PREFIXED (agents/mcp/util.py), so they match
        tools_server.py function names directly.
      - Guardrail + model exceptions are RE-RAISED at the END of the stream_events()
        iteration (RunResultStreaming._stored_exception) — the except blocks below
        sit OUTSIDE the loop. Because this coroutine is detached from every
        connection, no failure can ever become an HTTP 500: every path lands an
        in-stream terminal frame.
      - RunResultStreaming.cancel() is a SYNC method — call it without await.
    """
    conversation = []
    for msg in history:
        conversation.append({"role": msg.role, "content": msg.content})
    conversation.append({"role": "user", "content": message})

    server, request_dropsync = _new_request_agent(user_id)

    # Declared before try: the finally block retires it, and an early cancel must
    # not hit an unbound name.
    next_event: asyncio.Task | None = None
    try:
        await server.connect()
        result = Runner.run_streamed(
            request_dropsync,
            conversation,
            run_config=run_config,
            max_turns=MAX_TURNS,
        )
        run.result = result

        last_activity: tuple | None = None  # (phase, tool) — emit only on CHANGE

        def activity_frame(payload: dict) -> str | None:
            nonlocal last_activity
            key = (payload.get("phase"), payload.get("tool"))
            if key == last_activity:
                return None
            last_activity = key
            return _sse("activity", payload)

        # Immediate "generating" so a viewer shows a label from the first moment
        # (the client translates phases; the backend only reports them).
        first = activity_frame({"phase": "generating"})
        if first:
            run.frames.append(first)

        events = result.stream_events().__aiter__()
        keepalive_streak = 0
        streamed_text = False  # any delta sent since the last reset
        while True:
            if next_event is None:
                next_event = asyncio.create_task(events.__anext__())
            done, _pending = await asyncio.wait({next_event}, timeout=15.0)
            if not done:
                # Silent gap (e.g. a long-running tool — the MCP timeout is 60s).
                # There is no connection to keep alive here, but a long streak
                # still means something hung: bail with an error terminal
                # instead of waiting forever (~3 minutes with no event at all).
                keepalive_streak += 1
                if keepalive_streak > 12:
                    _finish_run(
                        run,
                        "error",
                        _sse("error", {"kind": "busy", "message": "The assistant took too long. Please try again."}),
                    )
                    return
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
                    run.frames.append(_sse("delta_reset", {}))
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
                        run.frames.append(_sse("delta", {"text": delta}))
            if frame:
                run.frames.append(frame)

        # Iteration finished without exception → run complete; reuse /chat's
        # post-run logic. to_thread: the firebase-admin get inside is a blocking
        # RPC — keep it off the event loop so a slow Firestore read can't stall
        # other concurrent runs.
        if run.cancel_requested:
            # A cancel landed while the final event was in flight — discard the
            # result (Stop semantics) instead of doing the preview work.
            _finish_run(run, "cancelled", _sse("error", {"kind": "cancelled", "message": "Stopped."}))
            return
        preview_drop_id, preview_ws_id = await asyncio.to_thread(_preview_from_result, result)
        _finish_run(run, "completed", _sse("final", {
            "response": result.final_output,
            "previewDropId": preview_drop_id,
            "previewWorkspaceId": preview_ws_id,
        }))

    except InputGuardrailTripwireTriggered as e:
        _finish_run(run, "completed", _sse("final", {
            "response": _guardrail_message(e),
            "previewDropId": None,
            "previewWorkspaceId": None,
        }))

    except MaxTurnsExceeded:
        # Step budget exhausted — an assistant-voice explanation delivered as a
        # normal final reply, not an in-stream error.
        _finish_run(run, "completed", _sse("final", {
            "response": _MAX_TURNS_MESSAGE,
            "previewDropId": None,
            "previewWorkspaceId": None,
        }))

    except asyncio.CancelledError:
        # The runner task itself was cancelled (the fallback cancel path).
        # Swallowing is legal — a task may complete normally after catching
        # CancelledError — and required here so the terminal always lands for
        # waiting viewers.
        _finish_run(run, "cancelled", _sse("error", {"kind": "cancelled", "message": "Stopped."}))

    except Exception as e:
        # Never forward str(e) (provider/model internals) to the browser — log
        # the real cause and land a classified in-stream error instead.
        _log.exception("chat run: run failed")
        kind, message = _classify_provider_error(e)
        _finish_run(run, "error", _sse("error", {"kind": kind, "message": message}))

    finally:
        # Retire the pending __anext__ task so a mid-run exit never leaves it
        # dangling; consume any stored exception so asyncio doesn't log
        # "exception was never retrieved".
        if next_event is not None:
            if not next_event.done():
                next_event.cancel()
            else:
                try:
                    next_event.exception()
                except (asyncio.CancelledError, StopAsyncIteration, Exception):
                    pass

        async def _teardown() -> None:
            # Subprocess cleanup ONLY — run cancellation is exclusively
            # _genuinely_cancel_run's job. Cancelling an already-finished run
            # reaches into the response machinery and splashes a bogus
            # "Exception in ASGI application" into the log.
            await server.cleanup()

        # Shielded: if this coroutine is being cancelled right now, the shield
        # lets the subprocess cleanup finish anyway.
        try:
            await asyncio.shield(_teardown())
        except Exception:
            pass

        # Belt-and-braces: no code path may leave a run without a terminal — a
        # viewer would keepalive forever. Every path above lands one; this only
        # catches a hypothetical bug.
        if run.finished_at is None:
            _finish_run(run, "error", _sse("error", {"kind": "busy", "message": "The assistant stopped unexpectedly. Please try again."}))


async def _follow_run(run: _ChatRun):
    """SSE view onto a run: replay the whole frame log, then follow live until the
    terminal frame is delivered. Shared by GET /chat/runs/{id}/stream and the
    legacy /chat/stream wrapper.

    Deliberately polling (0.25s tick): the log is append-only and each viewer
    keeps a private cursor, which makes multi-viewer replay trivially safe —
    the ≤250ms added latency is imperceptible behind the frontend's smooth-
    reveal buffering. Keepalive comments are per-viewer (never stored in the
    log) and double as liveness probes: a write to a dead socket lets Starlette
    cancel this generator. No viewer-side bail cap — the runner self-terminates
    (~3 min) and the terminal it lands is what closes us."""
    cursor = 0
    last_emit = time.monotonic()
    run.viewers += 1
    try:
        while True:
            new = run.frames[cursor:]
            if new:
                cursor += len(new)
                for frame in new:
                    yield frame
                last_emit = time.monotonic()
                continue
            if run.status != "running":
                return  # terminal frame delivered above — close
            if time.monotonic() - last_emit >= 15.0:
                yield ": keepalive\n\n"
                last_emit = time.monotonic()
                continue
            await asyncio.sleep(0.25)
    finally:
        run.viewers -= 1


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


@app.post("/chat/runs", response_model=RunStartResponse)
async def start_chat_run(req: RunStartRequest, user_id: str = Depends(verify_user)):
    """Start (or idempotently resume) a resumable chat run.

    Returns a run ticket immediately; the agent work happens in a detached task
    and its stream is (re)read via GET /chat/runs/{run_id}/stream — a client
    network hiccup just re-attaches and replays, it never loses the answer.
    Re-sending the SAME client_request_id returns the SAME run (no second run,
    no second quota charge); the quota gate runs only for genuinely new runs.
    """
    run = await _start_or_get_run(user_id, req.message, req.history, req.client_request_id)
    return RunStartResponse(run_id=run.run_id, status=run.status)


@app.get("/chat/runs/{run_id}/stream")
async def stream_chat_run(run_id: str, user_id: str = Depends(verify_user)):
    """SSE view onto a run — same frame vocabulary as /chat/stream. Replays the
    full log from frame 0, then follows live until the terminal frame. Attaching
    to an already-finished run replays instantly and closes. No quota gate:
    attaching to an existing run is free. Unknown or not-yours → 404 (never
    confirm another user's run exists) — the client treats attach-404 as a
    give-up signal (run evicted after ~10 min, or the Space restarted)."""
    run = _get_owned_run(run_id, user_id)
    _sweep_runs()
    return StreamingResponse(
        _follow_run(run),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # nginx-style proxies: do not buffer this stream
        },
    )


@app.post("/chat/runs/{run_id}/cancel", response_model=RunCancelResponse)
async def cancel_chat_run(run_id: str, user_id: str = Depends(verify_user)):
    """Genuinely stop a run (Stop button / panel close — saves model quota).
    Idempotent: a run that already reached its terminal returns its status
    untouched; cancel racing completion resolves to whichever landed first.

    The stop-memory summary is returned ONLY when this call genuinely cancelled
    the run — a run that already finished, or a second (idempotent) cancel,
    returns its status without a summary, so exactly one client can ever save
    the stop turn (single writer)."""
    run = _get_owned_run(run_id, user_id)
    _sweep_runs()
    if run.status == "running":
        _genuinely_cancel_run(run)
        return RunCancelResponse(status="cancelled", summary=run.cancel_summary)
    return RunCancelResponse(status=run.status)


@app.post("/chat/stream")
async def chat_stream(req: ChatRequest, user_id: str = Depends(verify_user)):
    """Streaming variant of /chat: same auth, quota gate, agent setup, and final
    payload — but the response is a text/event-stream that reports what the agent
    is doing while it works. Consumed by src/lib/agentActivity.ts in the frontend
    (one-shot path / deploy-order fallback; new clients use POST /chat/runs +
    GET /chat/runs/{id}/stream so they can reconnect after a network hiccup).

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

    Implementation notes:
      - Thin wrapper over the resumable-run machinery: start a run (quota gate
        inside _start_or_get_run — its 429 + Retry-After still escapes as JSON
        BEFORE any SSE headers; a fresh internal client_request_id per POST,
        because old clients send none) and attach to it in one response.
      - Client disconnect (Stop button / panel close) STILL genuinely cancels
        the run — the quota-saving behavior of the old implementation: the only
        viewer of a legacy run is gone and old clients can never re-attach.
      - One observable delta vs the old inline implementation: an MCP
        server.connect() failure now surfaces as an in-stream error event
        instead of a pre-stream HTTP 500 (the run executes detached) — same
        client outcome (saved error turn).
      - NEVER add GZip/compression middleware to this app — it buffers
        text/event-stream.
    """
    run = await _start_or_get_run(user_id, req.message, req.history, secrets.token_urlsafe(24))

    async def legacy_attach():
        client_gone = False
        try:
            async for frame in _follow_run(run):
                yield frame
        except asyncio.CancelledError:
            client_gone = True
            raise
        finally:
            # Old-client disconnect semantics preserved: no re-attach is coming,
            # so stop the run instead of burning model quota into the void. The
            # cancel calls are synchronous — nothing here needs shielding.
            if client_gone:
                _genuinely_cancel_run(run)

    return StreamingResponse(
        legacy_attach(),
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
