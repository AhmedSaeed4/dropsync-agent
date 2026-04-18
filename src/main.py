import sys
import os
from pathlib import Path

# Add src/ to Python path so tools_server can import config
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from agents import Runner, InputGuardrailTripwireTriggered
from agents.mcp import MCPServerStdio
from firebase_admin import auth as firebase_auth

from config import run_config
from agent import dropsync_agent

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


# ── Models ──────────────────────────────────────────────────────

class HistoryMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[HistoryMessage] = []


class ChatResponse(BaseModel):
    response: str


# ── Endpoints ───────────────────────────────────────────────────

@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, user_id: str = Depends(verify_user)):
    """Run the DropSync agent with MCP tools and conversation history."""
    # Build conversation: system context + history + new message
    conversation = []

    # Add previous messages
    for msg in req.history:
        conversation.append({"role": msg.role, "content": msg.content})

    # Add new message with user_id context
    conversation.append({"role": "user", "content": f"[user_id: {user_id}]\n{req.message}"})

    tools_server_path = str(Path(__file__).parent / "tools_server.py")

    # Explicitly pass env vars to subprocess (HF Spaces Docker needs this)
    _sub_env = {**os.environ}

    server = MCPServerStdio(
        params={
            "command": sys.executable,
            "args": [tools_server_path],
            "env": _sub_env,
        },
        client_session_timeout_seconds=60,
    )

    dropsync_agent.mcp_servers = [server]

    try:
        await server.connect()
        result = await Runner.run(
            dropsync_agent,
            conversation,
            run_config=run_config,
        )
        return ChatResponse(response=result.final_output)

    except InputGuardrailTripwireTriggered as e:
        return ChatResponse(
            response="I can't access drops in the 'password' category. "
                     "To view or manage your saved passwords, please use the DropSync app directly."
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        await server.cleanup()
        dropsync_agent.mcp_servers = []


@app.get("/health")
async def health():
    return {"status": "ok", "model": "kimi-k2.5"}


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
