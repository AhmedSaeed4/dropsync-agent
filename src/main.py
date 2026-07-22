import sys
import os
from pathlib import Path
from typing import Literal

# Add src/ to Python path so tools_server can import config
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from agents import Runner, InputGuardrailTripwireTriggered, handoff
from agents.mcp import MCPServerStdio
from agents.items import ToolCallItem
from openai.types.responses.response_output_item import McpCall
from firebase_admin import auth as firebase_auth

from config import run_config, MODEL_NAME, db
from agent import dropsync_agent, knowledge_agent

app = FastAPI(title="DropSync Agent API")

# CORS — reads allowed origins from env (comma-separated)
# Default: localhost:3000 for dev
_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins],
    allow_methods=["*"],
    allow_headers=["*"],
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
    # Build conversation: system context + history + new message
    conversation = []

    # Add previous messages
    for msg in req.history:
        conversation.append({"role": msg.role, "content": msg.content})

    # Add new message (caller identity is NOT pasted into the prompt — it travels
    # out-of-band via DROPSYNC_VERIFIED_UID in the per-request subprocess env).
    conversation.append({"role": "user", "content": req.message})

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

    # SECURITY (CRITICAL — race fix): clone the agents PER REQUEST. Never
    # mutate the shared module-level dropsync_agent.mcp_servers — concurrent
    # /chat requests race on that attribute (await server.connect() below
    # yields to the event loop, letting a second request overwrite
    # dropsync_agent.mcp_servers before Runner.run reads it, which would run
    # request A's agent against request B's server/subprocess and serve B's
    # DROPSYNC_VERIFIED_UID to A — full cross-user data leak). Each request
    # gets its own private agent+server pair via clone(); the shared
    # dropsync_agent / knowledge_agent are never touched.
    request_dropsync = dropsync_agent.clone(mcp_servers=[server])
    request_knowledge = knowledge_agent.clone()

    # Rewire handoffs between the per-request clones so the dropsync <->
    # knowledge handoff chain stays intact and never targets a shared
    # module-level agent. Groq needs the relaxed schema (non-OpenAI providers
    # reject the SDK's strict handoff schema — see agent.py:309-316).
    _req_kh = handoff(request_knowledge)
    _req_kh.input_json_schema = {"type": "object", "properties": {}}
    _req_kh.strict_json_schema = False
    _req_dh = handoff(request_dropsync)
    _req_dh.input_json_schema = {"type": "object", "properties": {}}
    _req_dh.strict_json_schema = False
    request_dropsync.handoffs = [_req_kh]
    request_knowledge.handoffs = [_req_dh]

    try:
        await server.connect()
        result = await Runner.run(
            request_dropsync,
            conversation,
            run_config=run_config,
        )
        response = result.final_output

        # Debug: log what's in result.new_items
        # Inspect tool call history for preview_drop calls
        preview_drop_id = None
        for item in result.new_items:
            if hasattr(item, 'raw_item') and item.raw_item:
                call = item.raw_item
                # Check name attribute on any tool call (MCP tools show as ResponseFunctionToolCall)
                call_name = getattr(call, 'name', None)
                if call_name == "preview_drop":
                    args_raw = getattr(call, 'arguments', '{}')
                    import json
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

        return ChatResponse(
            response=response,
            previewDropId=preview_drop_id,
            previewWorkspaceId=preview_ws_id,
        )

    except InputGuardrailTripwireTriggered as e:
        # The guardrail carries its verdict (incl. category) in output_info.
        # Default to the injection message if the category can't be read.
        category = None
        try:
            category = (e.guardrail_result.output.output_info or {}).get("category")
        except Exception:
            category = None
        if category == "password":
            msg = (
                "I can't open the contents of your password drops from chat — for security, "
                "those stay private to the DropSync app. Open the app to view or manage them. "
                "(I can still tell you how many you have if you ask for your storage stats.)"
            )
        else:
            # injection — or category missing/unreadable/unknown — single safe message
            msg = (
                "I can't follow instructions that try to override my rules or safety settings. "
                "If you're trying to get something done with your drops, just tell me plainly "
                "what you need and I'll help!"
            )
        return ChatResponse(response=msg)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        await server.cleanup()


@app.get("/health")
async def health():
    return {"status": "ok", "model": MODEL_NAME}


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
