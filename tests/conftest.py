"""Safe import environment for the test suite.

The real .env is NEVER opened, printed, or edited: dotenv is stubbed to a no-op,
Firebase is stubbed wholesale (no certificate is ever parsed), and config's import-time
demands are satisfied with throwaway dummy values. Every service client (db, OpenAI,
R2) is faked by the tests themselves. A process-wide audit hook makes any attempt to
open a .env file fail loudly.
"""
import os
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def _block_env_opens(event, args):
    if event == "open" and isinstance(args[0], str) and args[0].endswith("/.env"):
        raise RuntimeError("AUDIT: a .env file open was attempted in tests: " + args[0])


sys.addaudithook(_block_env_opens)

os.environ.setdefault("FIREBASE_PRIVATE_KEY", "test-only-dummy-value")
os.environ.setdefault("API_KEY", "test-only-dummy-value")

_dotenv = types.ModuleType("dotenv")
_dotenv.load_dotenv = lambda *args, **kwargs: False
_dotenv.dotenv_values = lambda *args, **kwargs: {}
_dotenv.find_dotenv = lambda *args, **kwargs: ""


def _dotenv_getattr(name):
    if name == "load_dotenv":
        return _dotenv.load_dotenv
    if name == "dotenv_values":
        return _dotenv.dotenv_values
    if name == "find_dotenv":
        return _dotenv.find_dotenv
    raise AttributeError("dotenv stub has no attribute " + repr(name))


_dotenv.__getattr__ = _dotenv_getattr
sys.modules["dotenv"] = _dotenv

_firebase = types.ModuleType("firebase_admin")
_firebase._apps = set()
_credentials = types.ModuleType("firebase_admin.credentials")
_credentials.Certificate = lambda info: types.SimpleNamespace(info=info)
_firestore = types.ModuleType("firebase_admin.firestore")
_firestore.client = lambda **kwargs: None
_firestore.transactional = lambda fn: fn
_firestore.SERVER_TIMESTAMP = "SERVER_TIMESTAMP"


class _DeleteFieldSentinel:
    def __repr__(self):
        return "DELETE_FIELD"


_firestore.DELETE_FIELD = _DeleteFieldSentinel()
_auth = types.ModuleType("firebase_admin.auth")
_firebase.credentials = _credentials
_firebase.firestore = _firestore
_firebase.auth = _auth
_firebase.initialize_app = lambda cred, options=None: _firebase._apps.add("test")
sys.modules["firebase_admin"] = _firebase
sys.modules["firebase_admin.credentials"] = _credentials
sys.modules["firebase_admin.firestore"] = _firestore
sys.modules["firebase_admin.auth"] = _auth
