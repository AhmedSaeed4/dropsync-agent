---
title: Dropsync Agent
emoji: 🤖
colorFrom: indigo
colorTo: green
sdk: docker
pinned: false
---

# DropSync Agent Backend

AI-powered backend for [DropSync](https://github.com/AhmedSaeed4/dropsync) — a secure, temporary file sharing app. Built with FastAPI, OpenAI Agents SDK, and MCP (Model Context Protocol).

## What It Does

- Chat with your drops using natural language
- Create, search, list, and delete text drops through AI
- Create shared workspaces with auto-generated invite codes
- All drops are end-to-end encrypted (AES-256-GCM)
- Password-category drops are protected by a two-layer guardrail (input guardrail + tool-level block)

## Tech Stack

- **Python 3.13** + **FastAPI** + **Uvicorn**
- **OpenAI Agents SDK** with MCP tools
- **Groq** (openai/gpt-oss-120b) for inference
- **Firebase Admin SDK** for auth and Firestore
- **Cryptography** (AES-256-GCM, ECDH key exchange)

## Tools Available to the Agent

| Tool | Description |
|------|-------------|
| `list_drops` | List all drops with decrypted content previews |
| `search_drops` | Search drops by name, content, or category |
| `get_drop` | Get full details of a specific drop |
| `create_drop` | Create a new encrypted text drop |
| `delete_drop` | Delete a drop |
| `list_workspaces` | Show user's workspaces |
| `create_workspace` | Create a new workspace with encryption key |
| `get_storage_stats` | Show storage usage and limits |

## Getting Started

### Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) package manager
- Groq API key
- Firebase project with Admin SDK credentials

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
# Groq API
GROQ_API_KEY=your_groq_key

# OpenAI API (optional — for agent tracing/guardrails)
OPENAI_API_KEY_FOR_TRACE=your_openai_key

# Firebase Admin
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_CLIENT_EMAIL=your_client_email
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nyour_key\n-----END PRIVATE KEY-----\n"

# Server config
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
# {"status":"ok","model":"openai/gpt-oss-120b"}
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/chat` | POST | Send a message to the AI agent (requires Firebase auth) |
| `/health` | GET | Health check |

### Chat Example

```bash
curl -X POST http://localhost:8000/chat \
  -H "Authorization: Bearer <firebase-id-token>" \
  -H "Content-Type: application/json" \
  -d '{"message": "list my drops"}'
```

## Architecture

```
User → Frontend (Next.js) → Agent Backend (FastAPI)
                                ↓
                           OpenAI Agents SDK
                                ↓
                        MCP Tools Server (stdio)
                                ↓
                          Firebase Firestore
```

- The agent connects to an MCP tools server via stdio for each request
- Tools handle encryption/decryption automatically
- Input guardrail blocks password-category access attempts
- All operations require Firebase authentication

## Security

- **E2E Encryption**: Personal drops use ECDH + AES-256-GCM, workspace drops use shared secret + AES-256-GCM
- **Auth**: Every request requires a valid Firebase ID token
- **Guardrails**: Two-layer password protection (LLM classifier + hard tool block)
- **No secrets in code**: All credentials loaded from environment variables

## License

MIT
