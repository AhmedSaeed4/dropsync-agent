---
title: Dropsync Agent
emoji: 🤖
colorFrom: indigo
colorTo: green
sdk: docker
pinned: false
---

# DropSync Agent Backend

AI-powered backend for [DropSync](https://github.com/AhmedSaeed4/dropsync) — a secure, temporary file-sharing and collaboration app. Built with FastAPI, the OpenAI Agents SDK, and MCP (Model Context Protocol).

The frontend's in-app AI assistant (chat panel → AI tab) talks to this service: it can search, create, update, move, copy, and delete drops, set reminders, manage workspaces and categories, and answer questions about how the app works.

## What It Does

- Chat with your drops using natural language — search, list, preview, create, update, move, copy, and delete text drops
- Create workspaces with auto-generated invite codes; join by invite code
- Fuzzy search — handles typos and misspellings across names, content, and categories
- Enforces per-workspace access control (personal drops are owner-only; workspace drops require membership)
- Sets, changes, and clears in-app reminders on text drops
- Password-category drops are protected by a three-layer defense (input guardrail + hard tool-level block + per-tool access checks)
- Trusted-tier enforcement — never-expiring ("forever") drops can only be created/kept by the owner or trusted users
- Knowledge agent answers "how does DropSync work?" questions without touching any data
- Per-user message limits (trusted users unlimited) — see **Limits**

## Architecture

```
Frontend (Next.js) ──POST /chat──▶ FastAPI (main.py)
                                      │  verify Firebase ID token → uid
                                      │  per-user quota gate (usage_limit.py)
                                      │  spawn FRESH MCP subprocess per request
                                      ▼
                              OpenAI Agents SDK (agent.py)
                                 ├─ DropSync Assistant (dropsync_agent)  — acts on data via MCP tools
                                 ├─ DropSync Knowledge (knowledge_agent) — app Q&A, no tools
                                 └─ PasswordGuardrail (input guardrail)  — LLM classifier, runs first
                                      │  bidirectional handoffs between assistant ⇄ knowledge
                                      ▼
                          MCP Tools Server (tools_server.py, stdio)
                                      │  Firestore reads/writes via Firebase Admin SDK
                                      │  decryption/encryption (decrypt.py)
                                      │  R2 image fetch/re-upload (r2.py)
                                      ▼
                                 Firebase Firestore
```

Key design points:

- **One MCP subprocess per request** — a fresh `tools_server.py` process is spawned (and cleaned up) for every `/chat` call. Nothing is pooled or reused across requests.
- **Caller identity is LLM-unforgeable** — the verified Firebase uid is injected into the subprocess environment as `DROPSYNC_VERIFIED_UID`. Tool parameters no longer accept a `user_id`, so the model has no channel to influence identity; `_verified_uid()` fails closed on a missing/invalid value.
- **Agents are cloned per request** — each request gets its own agent + MCP server pair, so concurrent requests can never cross wires (a race on the shared module-level agent would serve one user's identity to another).
- **Two agents with bidirectional handoff** — the assistant (has tools, acts on data) hands off to the knowledge agent for pure "how does X work" questions, and the knowledge agent hands back when an action is needed.
- **Admin SDK everywhere** — the backend bypasses `firestore.rules`, so every tool enforces authorization itself: workspace membership checks (`_is_workspace_member`), personal-drop ownership checks, and the trusted-tier gate (`is_trusted_caller`) before any write.

## Tools Available to the Agent

| Tool | Description |
|------|-------------|
| `list_drops` | List drops (personal or per-workspace) with decrypted content previews |
| `search_drops` | Fuzzy search across all accessible drops by name, content, or category (typo-tolerant, scored, top 10) |
| `get_drop` | Full details of a specific drop, including decrypted content |
| `preview_drop` | Open a drop in the frontend UI preview (returns drop id + workspace id) |
| `create_drop` | Create a new encrypted text drop (categories, expiration, optional reminder) |
| `update_drop` | Update a text drop's name, content (re-encrypted), categories, expiration, and/or reminder |
| `delete_drop` | Delete a drop (requires explicit user confirmation, per agent rules) |
| `move_drop` | Move a text drop between workspaces — content and attached images re-encrypted, categories preserved |
| `copy_drop` | Duplicate a text drop into another workspace, original untouched |
| `list_workspaces` | List the user's workspaces with role, member count, and invite code |
| `create_workspace` | Create a workspace with an auto-generated encryption key and invite code |
| `join_workspace` | Join a workspace with a 6-character invite code |
| `list_categories` | List categories with live drop-usage counts (personal or per-workspace) |
| `delete_category` | Delete a custom category (built-ins `password`/`link` cannot be deleted) |
| `get_storage_stats` | Storage stats with per-workspace breakdown (password drops counted, content hidden) |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/chat` | POST | Run the agent on a message + conversation history (Firebase auth required) |
| `/health` | GET | Health check — returns `{"status": "ok", "model": "<live model>"}` |

### Chat Request

```json
{
  "message": "list my drops",
  "history": [
    { "role": "user", "content": "hi" },
    { "role": "assistant", "content": "Hello! How can I help?" }
  ]
}
```

- `message` — the new user message
- `history` — optional previous turns; **only `user`/`assistant` roles are accepted** (a `system` role is rejected at the request boundary)
- Auth: `Authorization: Bearer <firebase-id-token>`

### Chat Response

```json
{
  "response": "I found 2 drops: …",
  "previewDropId": "abc123",
  "previewWorkspaceId": "ws-456"
}
```

- `previewDropId` / `previewWorkspaceId` are present when the agent called `preview_drop`, letting the frontend open that drop in the UI.

## Security

- **Auth**: every `/chat` request requires a valid Firebase ID token; the caller's uid is verified server-side and never trusted from the body or model
- **Identity channel**: `DROPSYNC_VERIFIED_UID` travels out-of-band via a per-request subprocess env — the model cannot read or override it
- **Password protection (3 layers)**:
  1. **Input guardrail** — an LLM classifier (`PasswordGuardrail`) runs before the main agent and blocks password-content access attempts and jailbreak/injection attempts
  2. **Tool-level block** — every data tool independently rejects `password`-category drops (checks both the modern `categories` array and legacy `category` field)
  3. **Access control** — every tool re-verifies ownership/membership before reading or writing
- **Guardrail fail-open**: if the classifier errors, the request proceeds — the tool-level hard blocks are the real boundary, so a transient classifier failure leaks nothing
- **Trusted-tier gate**: `is_trusted_caller` (owner or `tier == 'trusted'`) is enforced on every forever-drop create/update/move write, defaulting to *standard* on any error (fail-closed)
- **Encryption**: drops are AES-256-GCM encrypted — personal drops via ECDH-derived keys, workspace drops via the shared workspace key; the backend decrypts on the fly so the agent can read (non-password) content, matching the app's design (not zero-knowledge — see the app's Privacy page)
- **No secrets in code**: all credentials come from environment variables

## Limits

| Limit | Value |
|-------|-------|
| Agent messages | 5 per hour + 25 per day (rolling windows, UTC) — **trusted users unlimited & untracked** |
| Create/copy/move per request | 7 drops max per single message (soft guardrail; no overall cap) |
| Categories per drop | 3 |
| Forever drops | owner / trusted tier only |

## Getting Started

### Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) package manager
- An LLM provider API key (Groq or Gemini — the backend is provider-switchable)
- Firebase project with Admin SDK credentials (must share the same Firestore as the frontend app)

### Installation

1. Clone the repo
```bash
git clone https://github.com/AhmedSaeed4/dropsync-agent.git
cd dropsync-agent
```

2. Install dependencies
```bash
uv sync
```

3. Create `.env` with your credentials

```env
# ── LLM provider (Groq ⇄ Gemini switchable) ────────────────────
API_KEY=your_provider_api_key
BASE_URL=https://api.groq.com/openai/v1          # Groq
# or Gemini: https://generativelanguage.googleapis.com/v1beta/openai/
MODEL_NAME=openai/gpt-oss-120b                   # Groq model (set per provider)
# or MODEL_NAME=gemini-3.5-flash-lite (current live Gemini model — see GEMINI-MODEL-SWAP.md) for Gemini

# OpenAI API (optional — for agent tracing/guardrails)
OPENAI_API_KEY_FOR_TRACE=your_openai_key

# ── Firebase Admin ─────────────────────────────────────────────
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_CLIENT_EMAIL=your_client_email
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nyour_key\n-----END PRIVATE KEY-----\n"

# ── Cloudflare R2 (optional — required only for agent move/copy
#    of text drops with attached images, which re-encrypt them) ──
R2_ACCOUNT_ID=your_cloudflare_account_id
R2_ACCESS_KEY_ID=your_r2_access_key
R2_SECRET_ACCESS_KEY=your_r2_secret_key
R2_BUCKET_NAME=dropsync-files
R2_PUBLIC_URL=https://pub-xxxxx.r2.dev

# ── Server config ───────────────────────────────────────────────
HOST=0.0.0.0
PORT=8000

# CORS (comma-separated origins)
CORS_ORIGINS=http://localhost:3000
```

4. Run the server
```bash
uv run uvicorn src.main:app --host 0.0.0.0 --port 8000
```

5. Verify it's running
```bash
curl http://localhost:8000/health
# {"status":"ok","model":"<your MODEL_NAME>"}
```

### Chat Example

```bash
curl -X POST http://localhost:8000/chat \
  -H "Authorization: Bearer <firebase-id-token>" \
  -H "Content-Type: application/json" \
  -d '{"message": "list my drops"}'
```

## Tests

```bash
uv run python -m unittest discover -s tests
```

Unit tests cover the MCP tool layer (search scoring, list/search access control, decryption, expiry filtering) with mocked Firestore.

## Deployment

The Dockerfile runs the service on port **7860** (the port Hugging Face Spaces expects):

```bash
docker build -t dropsync-agent .
docker run -p 7860:7860 --env-file .env dropsync-agent
```

Deploy to the HF Space with:

```bash
git push hf main
```

Set the environment variables above as **Secrets** on the Space (API_KEY, BASE_URL, MODEL_NAME, FIREBASE_*, CORS_ORIGINS, and optionally OPENAI_API_KEY_FOR_TRACE + the R2_* vars).

## Repository Structure

```
src/
├── main.py          # FastAPI app: /chat + /health, auth, quota gate, per-request MCP subprocess
├── agent.py         # Agents: DropSync Assistant, DropSync Knowledge, PasswordGuardrail
├── tools_server.py  # MCP tools server (stdio): 15 tools over Firestore
├── decrypt.py       # AES-256-GCM + ECDH decryption/encryption (personal + workspace keys)
├── authz.py         # Trusted-tier check (owner / tier == 'trusted'), fail-closed
├── usage_limit.py   # Rolling per-user message quota (5/hr + 25/day) via Firestore transactions
├── r2.py            # Cloudflare R2 helpers (fetch/re-upload encrypted drop images)
└── config.py        # Env loading, Firebase Admin init, LLM client + model wiring
```

## License

MIT
