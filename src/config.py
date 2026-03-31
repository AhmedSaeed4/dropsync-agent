import os
from dotenv import load_dotenv
from openai import AsyncOpenAI
from agents import OpenAIChatCompletionsModel, RunConfig
import firebase_admin
from firebase_admin import credentials, firestore

load_dotenv()

# ── Tracing/Observability ────────────────────────────────────────
# Set OpenAI key for tracing (parallel, doesn't affect Groq responses)
# The Agents SDK uses OPENAI_API_KEY internally for tracing/guardrails
if os.getenv("OPENAI_API_KEY_FOR_TRACE"):
    os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY_FOR_TRACE")

# ── Firebase Admin ──────────────────────────────────────────────
if not firebase_admin._apps:
    cred = credentials.Certificate({
        "type": "service_account",
        "project_id": os.getenv("FIREBASE_PROJECT_ID"),
        "private_key_id": "1",
        "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
        "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
        "client_id": "",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    })
    firebase_admin.initialize_app(cred)

db = firestore.client()

# ── Groq Client ────────────────────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY not set in .env")

groq_client = AsyncOpenAI(
    api_key=GROQ_API_KEY,
    base_url="https://api.groq.com/openai/v1",
)

MODEL_NAME = "openai/gpt-oss-120b"

model = OpenAIChatCompletionsModel(
    model=MODEL_NAME,
    openai_client=groq_client,
)

run_config = RunConfig(
    model=model,
    model_provider=groq_client,
)
