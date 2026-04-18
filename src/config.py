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
    _pk = os.getenv("FIREBASE_PRIVATE_KEY")
    if not _pk:
        raise ValueError("FIREBASE_PRIVATE_KEY not set. Add it as a secret in your deployment platform.")
    cred = credentials.Certificate({
        "type": "service_account",
        "project_id": os.getenv("FIREBASE_PROJECT_ID"),
        "private_key_id": "1",
        "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
        "private_key": _pk.replace("\\n", "\n"),
        "client_id": "",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    })
    firebase_admin.initialize_app(cred)

db = firestore.client()

# ── LLM Client ──────────────────────────────────────────────────
API_KEY = os.getenv("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY not set in .env")

BASE_URL = os.getenv("BASE_URL", "https://coding-intl.dashscope.aliyuncs.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "kimi-k2.5")

llm_client = AsyncOpenAI(
    api_key=API_KEY,
    base_url=BASE_URL,
)

model = OpenAIChatCompletionsModel(
    model=MODEL_NAME,
    openai_client=llm_client,
)

run_config = RunConfig(
    model=model,
    model_provider=llm_client,
)
