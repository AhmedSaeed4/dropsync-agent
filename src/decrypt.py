"""
Encryption and decryption utilities for DropSync agent.
Handles both personal drops (ECDH + AES-256-GCM) and workspace drops (shared secret + AES-256-GCM).
"""

import base64
import json
import os
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
)

from config import db


def b64d(s: str) -> bytes:
    """Base64 decode with padding fix."""
    p = 4 - len(s) % 4
    if p != 4:
        s += "=" * p
    return base64.b64decode(s)


def b64e(data: bytes) -> str:
    """Base64 encode, no padding."""
    return base64.b64encode(data).decode().rstrip("=")


# ── Personal drops ───────────────────────────────────────────────
# Encryption chain:
#   masterKey → AES-GCM decrypt → private key (SEC1 DER, base64-wrapped)
#   ECDH(private, public) → raw shared secret
#   shared secret → AES-GCM decrypt → DEK (base64-wrapped)
#   DEK → AES-GCM decrypt → plaintext

def _get_shared_secret(user_id: str) -> bytes | None:
    """Derive ECDH shared secret from user's own key pair (self-encryption)."""
    uk = db.collection("userKeys").document(user_id).get()
    if not uk.exists:
        return None
    uk_data = uk.to_dict()

    # Decrypt private key: masterKey → AES-GCM → base64(SEC1 DER)
    master_key = b64d(uk_data["masterKey"])
    pk_b64 = AESGCM(master_key).decrypt(
        b64d(uk_data["iv"]),
        b64d(uk_data["encryptedPrivateKey"]),
        None,
    )
    pk_der = b64d(pk_b64.decode())
    private_key = load_der_private_key(pk_der, password=None)

    # Load public key (SPKI DER)
    public_key = load_der_public_key(b64d(uk_data["publicKey"]))

    # ECDH: raw shared secret (Web Crypto uses raw x-coordinate directly)
    return private_key.exchange(ECDH(), public_key)


def decrypt_personal_drop(user_id: str, drop_data: dict) -> str | None:
    """Decrypt a personal (non-workspace) encrypted text drop."""
    try:
        shared_secret = _get_shared_secret(user_id)
        if not shared_secret:
            return None

        # Parse encrypted DEK
        dek_info = json.loads(drop_data["encryptedDEK"])

        # Decrypt DEK: shared_secret → AES-GCM → base64(DEK bytes)
        dek_b64 = AESGCM(shared_secret).decrypt(
            b64d(dek_info["iv"]),
            b64d(dek_info["encryptedDEK"]),
            None,
        )
        dek_bytes = b64d(dek_b64.decode())

        # Decrypt content: DEK → AES-GCM → plaintext
        plaintext = AESGCM(dek_bytes).decrypt(
            b64d(drop_data["iv"]),
            b64d(drop_data["content"]),
            None,
        )
        return plaintext.decode("utf-8")

    except Exception as e:
        print(f"Error decrypting personal drop: {e}")
        return None


# ── Workspace drops ──────────────────────────────────────────────
# Encryption chain:
#   keySecret (UTF-8, first 32 bytes) → AES key
#   AES key → AES-GCM decrypt → base64(workspace key)
#   workspace key → AES-GCM decrypt → plaintext

def decrypt_workspace_drop(user_id: str, drop_data: dict) -> str | None:
    """Decrypt a workspace encrypted text drop."""
    try:
        workspace_id = drop_data.get("workspaceId")
        if not workspace_id:
            return None

        wk = db.collection("workspaceKeys").document(workspace_id).get()
        if not wk.exists:
            return None
        wk_data = wk.to_dict()

        # Derive AES key from secret (first 32 bytes)
        secret_bytes = wk_data["keySecret"].encode("utf-8")[:32].ljust(32, b"\x00")

        # Decrypt workspace key
        wk_bytes_b64 = AESGCM(secret_bytes).decrypt(
            b64d(wk_data["iv"]),
            b64d(wk_data["encryptedKey"]),
            None,
        )
        workspace_key = b64d(wk_bytes_b64.decode())

        # Decrypt content
        plaintext = AESGCM(workspace_key).decrypt(
            b64d(drop_data["iv"]),
            b64d(drop_data["content"]),
            None,
        )
        return plaintext.decode("utf-8")

    except Exception as e:
        print(f"Error decrypting workspace drop: {e}")
        return None


# ── Encryption ───────────────────────────────────────────────────

def encrypt_personal_drop(user_id: str, content: str) -> dict | None:
    """Encrypt content for a personal drop. Returns Firestore-ready dict fields."""
    try:
        shared_secret = _get_shared_secret(user_id)
        if not shared_secret:
            return None

        # Generate random DEK (32 bytes)
        dek_bytes = os.urandom(32)

        # Generate random IV for DEK encryption
        dek_iv = os.urandom(12)

        # Encrypt DEK with shared secret → base64(DEK bytes)
        dek_encrypted = AESGCM(shared_secret).encrypt(
            dek_iv,
            b64e(dek_bytes).encode(),
            None,
        )

        # Build encryptedDEK JSON (matches frontend format)
        encrypted_dek_json = json.dumps({
            "encryptedDEK": b64e(dek_encrypted),
            "iv": b64e(dek_iv),
        })

        # Generate random IV for content encryption
        content_iv = os.urandom(12)

        # Encrypt content with DEK
        content_encrypted = AESGCM(dek_bytes).encrypt(
            content_iv,
            content.encode("utf-8"),
            None,
        )

        return {
            "content": b64e(content_encrypted),
            "iv": b64e(content_iv),
            "encryptedDEK": encrypted_dek_json,
            "encrypted": True,
        }

    except Exception as e:
        print(f"Error encrypting personal drop: {e}")
        return None


def encrypt_workspace_drop(user_id: str, workspace_id: str, content: str) -> dict | None:
    """Encrypt content for a workspace drop. Returns Firestore-ready dict fields."""
    try:
        wk = db.collection("workspaceKeys").document(workspace_id).get()
        if not wk.exists:
            return None
        wk_data = wk.to_dict()

        # Derive AES key from secret (first 32 bytes)
        secret_bytes = wk_data["keySecret"].encode("utf-8")[:32].ljust(32, b"\x00")

        # Decrypt workspace key
        wk_bytes_b64 = AESGCM(secret_bytes).decrypt(
            b64d(wk_data["iv"]),
            b64d(wk_data["encryptedKey"]),
            None,
        )
        workspace_key = b64d(wk_bytes_b64.decode())

        # Generate random IV for content encryption
        content_iv = os.urandom(12)

        # Encrypt content with workspace key
        content_encrypted = AESGCM(workspace_key).encrypt(
            content_iv,
            content.encode("utf-8"),
            None,
        )

        return {
            "content": b64e(content_encrypted),
            "iv": b64e(content_iv),
            "encrypted": True,
        }

    except Exception as e:
        print(f"Error encrypting workspace drop: {e}")
        return None


# ── Main entry points ────────────────────────────────────────────

def decrypt_drop_content(user_id: str, drop_data: dict) -> str | None:
    """Decrypt a drop's content. Returns decrypted text or None."""
    if not drop_data.get("encrypted"):
        return drop_data.get("content")

    if drop_data.get("workspaceId"):
        return decrypt_workspace_drop(user_id, drop_data)
    else:
        return decrypt_personal_drop(user_id, drop_data)


def encrypt_drop_content(user_id: str, content: str, workspace_id: str | None = None) -> dict | None:
    """Encrypt content for a new drop. Returns Firestore-ready encryption fields."""
    if workspace_id:
        return encrypt_workspace_drop(user_id, workspace_id, content)
    else:
        return encrypt_personal_drop(user_id, content)
