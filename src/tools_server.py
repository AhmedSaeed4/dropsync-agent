"""
MCP server for DropSync Firestore tools.
Run as a standalone script — the agent connects via MCPServerStdio.
Supports decryption of both personal and workspace encrypted text drops.
Password-category drops are restricted — they cannot be listed, searched,
read, or deleted through the agent.
"""

import sys
import os

# Ensure this script's directory is on sys.path so imports work
# regardless of the working directory of the parent process
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

from mcp.server.fastmcp import FastMCP

from config import db
from decrypt import decrypt_drop_content, encrypt_drop_content, b64e, b64d, encrypt_personal_drop, encrypt_workspace_drop, _get_workspace_key_data, _decrypt_with_workspace_key, _encrypt_with_workspace_key
from r2 import fetch_from_r2, fetch_from_r2_by_key, upload_to_r2, delete_from_r2
from datetime import datetime, timezone, timedelta
from firebase_admin import firestore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
)
from difflib import SequenceMatcher
import json
import secrets
import os

mcp = FastMCP("dropsync-tools")

PASSWORD_DENIED = "Access denied — this drop is in the 'password' category and cannot be accessed through the AI assistant. Use the DropSync app directly."

BUILT_IN_CATEGORIES = {"password", "link"}


# ── Helpers ─────────────────────────────────────────────────────

def _is_password_drop(d: dict) -> bool:
    """True if the drop is in the password category.

    Checks both the canonical `categories` array AND the legacy singular
    `category` field (case-insensitive, whitespace-trimmed) — the frontend
    writes password drops as {category: null, categories: ["password"]}, so
    checking only `category` misses them. Defensive against None / non-dict /
    missing / non-str / non-list values so it can never throw.
    """
    if not isinstance(d, dict):
        return False
    cats = d.get("categories")
    if isinstance(cats, list):
        if any(isinstance(c, str) and c.strip().lower() == "password" for c in cats):
            return True
    cat = d.get("category")
    if isinstance(cat, str) and cat.strip().lower() == "password":
        return True
    return False


ACCESS_DENIED_WORKSPACE = "Access denied — you're not a member of this workspace."


def _is_workspace_member(user_id: str | None, workspace_id: str | None) -> bool:
    """True if user_id may read/write workspace-scoped data for workspace_id.

    Mirrors the firestore.rules workspace-read contract (members array OR ownerId)
    and the in-tool membership check already used by get_drop / delete_drop /
    preview_drop / move_drop / delete_category / update_drop. Returns True for
    personal context (workspace_id None / '' / 'none') so callers can gate the
    workspace branch without special-casing personal drops. A non-string truthy
    workspace_id (schema drift / corrupted doc) is treated as malformed and
    DENIED. Never raises — denies (returns False) on a missing workspace doc, a
    malformed members field, or any Firestore error rather than leaking data or
    surfacing a 500 to the LLM.
    """
    # Personal context: no workspace specified.
    if not workspace_id:
        return True
    # Malformed (non-string) workspace_id — deny (fail-closed) on a security gate.
    if not isinstance(workspace_id, str):
        return False
    # The model sometimes passes the literal string "None"; treat as personal.
    if workspace_id.lower() == "none":
        return True
    try:
        ws_doc = db.collection("workspaces").document(workspace_id).get()
    except Exception:
        return False
    if not ws_doc.exists:
        return False
    d = ws_doc.to_dict() or {}
    if user_id and user_id == d.get("ownerId"):
        return True
    members = d.get("members")
    # Guard against a corrupted non-list members field (a string would make `in`
    # a substring match). Deny unless it's a real list containing us.
    return isinstance(members, list) and user_id in members


_UID_DENIED = "Access denied — no verified user identity for this request."


def _verified_uid() -> str | None:
    """Return the LLM-unforgeable caller uid, or None to deny.

    SECURITY: this is the ONLY trusted source of caller identity. It reads
    DROPSYNC_VERIFIED_UID from os.environ, which main.py injects into the
    per-request MCP subprocess from the Firebase-verified token. The model
    cannot read or override os.environ (no tool exposes it), and user_id is no
    longer a tool parameter, so there is NO channel for the model to influence
    this value.

    Callers MUST deny (return _UID_DENIED) when this returns None. Never fall
    back to a model-supplied uid — the parameter does not exist.

    The subprocess MUST be fresh per request (main.py spawns via
    MCPServerStdio + connect/cleanup per /chat). A stale/corrupt value fails
    closed here rather than querying Firestore with garbage.
    """
    raw = os.environ.get("DROPSYNC_VERIFIED_UID")
    if not isinstance(raw, str):
        return None
    uid = raw.strip()
    # Firebase uids are non-empty, no whitespace, reasonable length.
    # A stale/corrupt/truncated value fails closed here.
    if not uid or len(uid) > 128 or any(c.isspace() for c in uid):
        return None
    return uid


def _score_query(query: str, name: str, category: str, content: str) -> float:
    """Score a drop against a multi-token query. Returns 0.0 for no match.
    Higher score = better match. Name matches weigh most, then category, then content."""
    tokens = query.lower().split()
    if not tokens:
        return 0.0

    name_lower = name.lower()
    cat_lower = (category or "").lower()
    content_lower = (content or "")[:300].lower()  # Only scan first 300 chars

    total_score = 0.0
    max_possible = len(tokens) * 3.0  # 3 fields * max weight

    for token in tokens:
        if len(token) < 2:
            continue
        token_score = 0.0

        # NAME: exact substring = 1.0, fuzzy = up to 0.9
        if token in name_lower:
            token_score = max(token_score, 1.0)
        elif len(name_lower) > 0:
            # Full string fuzzy
            name_ratio = SequenceMatcher(None, token, name_lower).ratio()
            token_score = max(token_score, name_ratio * 0.9)
            # Word-level fuzzy
            for nw in name_lower.split():
                word_ratio = SequenceMatcher(None, token, nw).ratio()
                if word_ratio >= 0.65:
                    token_score = max(token_score, word_ratio * 0.85)

        # CATEGORY: exact = 0.9, fuzzy = up to 0.8
        if cat_lower and token in cat_lower:
            token_score = max(token_score, 0.9)
        elif cat_lower:
            cat_ratio = SequenceMatcher(None, token, cat_lower).ratio()
            token_score = max(token_score, cat_ratio * 0.8)

        # CONTENT: exact = 0.7, fuzzy = up to 0.6
        if content_lower and token in content_lower:
            token_score = max(token_score, 0.7)
        elif content_lower:
            # Only fuzzy-match content if token is at least 3 chars (avoid noise)
            if len(token) >= 3:
                for cw in content_lower.split()[:50]:  # First 50 words only
                    cw_ratio = SequenceMatcher(None, token, cw).ratio()
                    if cw_ratio >= 0.7:
                        token_score = max(token_score, cw_ratio * 0.6)
                        break

        total_score += token_score

    if total_score <= 0:
        return 0.0
    return total_score / max_possible


def _get_workspace_name(ws_id: str) -> str:
    """Get workspace name from ID. Returns the ID if not found."""
    ws = db.collection("workspaces").document(ws_id).get()
    if ws.exists:
        return ws.to_dict().get("name", ws_id)
    return ws_id


def _format_drop(doc_id: str, d: dict, content_preview: str = "") -> str:
    """Format a drop for display. Shows workspace name (ID) if not personal."""
    image_info = ""
    if d.get("imageR2Key"):
        size = d.get("imageSize", 0) or 0
        if size >= 1024 * 1024:
            size_str = f"{size / (1024*1024):.1f}MB"
        else:
            size_str = f"{size / 1024:.0f}KB"
        image_info = f", has_image={size_str}"
    ws_id = d.get("workspaceId")
    ws_info = f"workspace={_get_workspace_name(ws_id)}({ws_id})" if ws_id else "workspace=Personal"
    return (
        f"- {d.get('name', 'untitled')} "
        f"(type={d.get('type', '?')}, "
        f"encrypted={d.get('encrypted', False)}, "
        f"category={d.get('category', 'none')}, "
        f"expires={d.get('expiresAt', 'never')}"
        f"{content_preview}{image_info}, "
        f"workspace_id={ws_id or 'null'}, "
        f"{ws_info}, "
        f"id={doc_id})"
    )


def _get_user_workspace_ids(user_id: str) -> list[str]:
    """Get IDs of all workspaces the user is a member of."""
    docs = db.collection("workspaces").where("members", "array_contains", user_id).stream()
    return [doc.id for doc in docs]


def _get_all_accessible_drops(user_id: str) -> list:
    """Get all drops a user can access: personal drops + drops from all joined workspaces.
    Deduplicates by document ID."""
    seen_ids = set()
    all_docs = []

    # 1. Personal drops (userId == me AND workspaceId == null)
    for doc in db.collection("drops").where("userId", "==", user_id).where("workspaceId", "==", None).stream():
        if doc.id not in seen_ids:
            seen_ids.add(doc.id)
            all_docs.append(doc)

    # 2. Workspace drops — no userId filter, all members see all drops
    for ws_id in _get_user_workspace_ids(user_id):
        for doc in db.collection("drops").where("workspaceId", "==", ws_id).stream():
            if doc.id not in seen_ids:
                seen_ids.add(doc.id)
                all_docs.append(doc)

    return all_docs


# ── Tools ───────────────────────────────────────────────────────

@mcp.tool()
def list_drops(workspace_id: str | None = None) -> str:
    """List drops for a user, optionally filtered by workspace.
    - No workspace_id (None): returns personal drops only (workspaceId == null).
    - With workspace_id: returns ALL drops in that workspace from ALL members.
    Password-category drops are excluded."""
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    # Handle case where model passes "None" as a string
    if workspace_id and workspace_id.lower() != "none":
        # Workspace drops — verify membership BEFORE reading. The Admin SDK
        # bypasses firestore.rules, so workspace access must be enforced here.
        if not _is_workspace_member(user_id, workspace_id):
            return ACCESS_DENIED_WORKSPACE
        # No userId filter — all members see all drops in the workspace
        docs = db.collection("drops").where("workspaceId", "==", workspace_id).stream()
    else:
        # Personal drops only (userId + workspaceId == null)
        docs = db.collection("drops").where("userId", "==", user_id).where("workspaceId", "==", None).stream()

    drops = []
    for doc in docs:
        d = doc.to_dict()

        # Skip password-category drops
        if _is_password_drop(d):
            continue

        # Decrypt content for preview
        content_preview = ""
        if d.get("type") == "text" and d.get("content"):
            decrypted = decrypt_drop_content(user_id, d)
            if decrypted:
                content_preview = f", content=\"{decrypted[:60]}\""

        drops.append(_format_drop(doc.id, d, content_preview))

    if not drops:
        return "No drops found."
    return "\n".join(drops)


@mcp.tool()
def search_drops(query: str) -> str:
    """Search drops by name, text content, or category. Searches through decrypted content too.
    Uses scoring and ranking — handles typos like 'bilal disord' matching 'AWS bilal'.
    Searches across personal drops AND all workspace drops the user has access to.
    Password-category drops are excluded from results."""
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    scored_results: list[tuple[float, str]] = []  # (score, formatted_string)
    query_lower = query.lower().strip()

    for doc in _get_all_accessible_drops(user_id):
        d = doc.to_dict()

        # Skip password-category drops
        if _is_password_drop(d):
            continue

        name = d.get("name", "")
        category = d.get("category") or ""

        # Decrypt content to search through it
        decrypted_content = ""
        if d.get("type") == "text" and d.get("content"):
            decrypted = decrypt_drop_content(user_id, d)
            if decrypted:
                decrypted_content = decrypted

        score = _score_query(query_lower, name, category, decrypted_content)

        # Minimum threshold: at least one token must match something
        tokens = query_lower.split()
        if score > 0.05:
            content_preview = f', content="{decrypted_content[:60]}"' if decrypted_content else ""
            scored_results.append((score, _format_drop(doc.id, d, content_preview)))

    if not scored_results:
        return f"No drops matching '{query}'. Try listing your drops to see what's available."

    # Sort by score descending, return top 10
    scored_results.sort(key=lambda x: -x[0])
    top_results = scored_results[:10]

    output_parts = []
    if top_results[0][0] < 0.3:
        output_parts.append(f"No exact matches for '{query}', but found similar:")
    for score, formatted in top_results:
        output_parts.append(formatted)

    return "\n".join(output_parts)


@mcp.tool()
def get_drop(drop_id: str) -> str:
    """Get full details for a specific drop, including decrypted content.
    For personal drops: only the owner can access. For workspace drops: any member can access.
    Password-category drops cannot be accessed."""
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    doc = db.collection("drops").document(drop_id).get()

    if not doc.exists:
        return f"Drop {drop_id} not found."

    d = doc.to_dict()

    # Access control: personal drops require ownership, workspace drops require membership
    ws_id = d.get("workspaceId")
    if ws_id:
        # Workspace drop — verify membership
        if not _is_workspace_member(user_id, ws_id):
            return ACCESS_DENIED_WORKSPACE
    else:
        # Personal drop — must be owner
        if d.get("userId") != user_id:
            return "Access denied — this drop belongs to another user."

    if _is_password_drop(d):
        return PASSWORD_DENIED

    lines = [
        f"Name: {d.get('name', 'untitled')}",
        f"Type: {d.get('type', '?')}",
        f"Workspace: {_get_workspace_name(ws_id)} ({ws_id})" if ws_id else "Workspace: Personal",
        f"Encrypted: {d.get('encrypted', False)}",
        f"Category: {d.get('category', 'none')}",
        f"Created: {d.get('createdAt', '?')}",
        f"Expires: {d.get('expiresAt', 'never')}",
        f"Size: {d.get('fileSize', 'N/A')} bytes",
    ]

    # Show image attachment info
    if d.get("imageR2Key"):
        img_size = d.get("imageSize", 0) or 0
        if img_size >= 1024 * 1024:
            img_size_str = f"{img_size / (1024*1024):.1f}MB"
        else:
            img_size_str = f"{img_size / 1024:.0f}KB"
        lines.append(f"Image attached: {img_size_str} {d.get('imageMimeType', 'image/*')}")

    # Decrypt and show content
    if d.get("type") == "text" and d.get("content"):
        decrypted = decrypt_drop_content(user_id, d)
        if decrypted:
            lines.append(f"Content: {decrypted}")
        else:
            lines.append("Content: [could not decrypt]")
    elif d.get("type") == "file":
        lines.append("Content: [file — use the DropSync app to download]")

    return "\n".join(lines)


@mcp.tool()
def delete_drop(drop_id: str) -> str:
    """Delete a drop.
    For personal drops: only the owner can delete. For workspace drops: any member can delete.
    Password-category drops cannot be deleted through the agent."""
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    doc_ref = db.collection("drops").document(drop_id)
    doc = doc_ref.get()

    if not doc.exists:
        return f"Drop {drop_id} not found."

    d = doc.to_dict()

    # Access control: personal drops require ownership, workspace drops require membership
    ws_id = d.get("workspaceId")
    if ws_id:
        if not _is_workspace_member(user_id, ws_id):
            return ACCESS_DENIED_WORKSPACE
    else:
        if d.get("userId") != user_id:
            return "Access denied — you can only delete your own drops."

    if _is_password_drop(d):
        return PASSWORD_DENIED

    doc_ref.delete()
    return f"Deleted drop '{d.get('name', drop_id)}'."


@mcp.tool()
def preview_drop(drop_id: str) -> str:
    """Get the drop ID and workspace ID needed to open a drop in the UI preview.
    Use this when the user asks to open, preview, or show a specific drop.
    Returns the drop details needed for the UI to open it."""
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    doc = db.collection("drops").document(drop_id).get()
    if not doc.exists:
        return f"Drop {drop_id} not found."

    d = doc.to_dict()

    # Access control
    ws_id = d.get("workspaceId")
    if ws_id:
        if not _is_workspace_member(user_id, ws_id):
            return ACCESS_DENIED_WORKSPACE
    else:
        if d.get("userId") != user_id:
            return "Access denied — you can only preview your own drops."

    ws_name = _get_workspace_name(ws_id) if ws_id else "Personal"
    return f"I'll open '{d.get('name', drop_id)}' for you."


@mcp.tool()
def move_drop(drop_id: str, target_workspace_id: str) -> str:
    """Move a drop from one workspace to another.
    Both the source and target must be workspaces (not personal drops).
    The user must be a member of both workspaces.
    Handles text drops with attached images — both content and images are re-encrypted.
    Categories are preserved and matched to the target workspace — missing categories are auto-created.
    Args:
        drop_id: ID of the drop to move.
        target_workspace_id: ID of the target workspace.
    """
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    doc_ref = db.collection("drops").document(drop_id)
    doc = doc_ref.get()

    if not doc.exists:
        return f"Drop {drop_id} not found."

    d = doc.to_dict()
    source_ws = d.get("workspaceId")

    # Block personal drops
    if not source_ws:
        return "Cannot move personal drops via chat. Use the DropSync app to move personal drops."

    # Block moving to personal
    if not target_workspace_id or target_workspace_id.lower() == "none":
        return "Cannot move workspace drops to personal via chat. Use the DropSync app."

    # Can't move to the same workspace
    if source_ws == target_workspace_id:
        return f"Drop is already in that workspace."

    # Verify membership in source workspace
    if not _is_workspace_member(user_id, source_ws):
        return "Access denied — you're not a member of the source workspace."

    # Verify membership in target workspace
    if not _is_workspace_member(user_id, target_workspace_id):
        return "Access denied — you're not a member of the target workspace."

    # Block password drops
    if _is_password_drop(d):
        return PASSWORD_DENIED

    # Only text drops can be moved via agent
    if d.get("type") != "text":
        return "Only text drops can be moved via chat. Use the app to move file drops."

    # Decrypt content with source workspace key
    src_name = _get_workspace_name(source_ws)
    tgt_name = _get_workspace_name(target_workspace_id)

    decrypted_content = decrypt_drop_content(user_id, d)
    if not decrypted_content:
        return "Failed to decrypt drop content. Cannot move."

    # Re-encrypt with target workspace key
    encrypted = encrypt_workspace_drop(user_id, target_workspace_id, decrypted_content)
    if not encrypted:
        return "Failed to re-encrypt content for target workspace."

    # Update Firestore
    update_data = {
        "workspaceId": target_workspace_id,
        "content": encrypted["content"],
        "iv": encrypted["iv"],
        "encrypted": True,
        "encryptedDEK": None,  # Remove personal DEK if present
        "category": None,
    }

    # Category matching: preserve and auto-create categories in target workspace
    source_categories = d.get("categories") or ([d.get("category")] if d.get("category") else [])
    if source_categories:
        resolved_categories = []
        custom_categories = []

        # Separate built-in from custom categories
        for cat_name in source_categories:
            if cat_name.lower().strip() in BUILT_IN_CATEGORIES:
                resolved_categories.append(cat_name.lower().strip())
            else:
                custom_categories.append(cat_name)

        # Query existing categories in target workspace
        if custom_categories:
            cat_docs = list(db.collection("categories")
                            .where("workspaceId", "==", target_workspace_id)
                            .limit(100).stream())
            existing_categories = {}
            for cat_doc in cat_docs:
                data = cat_doc.to_dict()
                existing_categories[data["name"].lower().strip()] = data["name"]

            for cat_name in custom_categories:
                name_lower = cat_name.lower().strip()
                if name_lower in existing_categories:
                    resolved_categories.append(existing_categories[name_lower])
                else:
                    db.collection("categories").add({
                        "name": name_lower,
                        "workspaceId": target_workspace_id,
                        "createdBy": user_id,
                        "createdAt": firestore.SERVER_TIMESTAMP,
                    })
                    existing_categories[name_lower] = name_lower
                    resolved_categories.append(name_lower)

        update_data["categories"] = resolved_categories
    else:
        update_data["categories"] = []

    # Handle attached image re-encryption
    old_image_r2_key = d.get("imageR2Key")
    if d.get("imageUrl") and d.get("imageIv"):
        encrypted_image = fetch_from_r2_by_key(d.get("imageR2Key"))
        if encrypted_image:
            source_key = _get_workspace_key_data(source_ws)
            if source_key:
                decrypted_image = _decrypt_with_workspace_key(encrypted_image, d["imageIv"], source_key)
                if decrypted_image:
                    target_key = _get_workspace_key_data(target_workspace_id)
                    if target_key:
                        re_encrypted = _encrypt_with_workspace_key(decrypted_image, target_key)
                        if re_encrypted:
                            upload_result = upload_to_r2(re_encrypted["content"])
                            update_data["imageUrl"] = upload_result["url"]
                            update_data["imageR2Key"] = upload_result["key"]
                            update_data["imageIv"] = re_encrypted["iv"]
                            if d.get("imageSize"):
                                update_data["imageSize"] = d["imageSize"]
                            if d.get("imageMimeType"):
                                update_data["imageMimeType"] = d["imageMimeType"]
                        else:
                            # Re-encryption failed — clear image
                            update_data["imageUrl"] = None
                            update_data["imageR2Key"] = None
                            update_data["imageIv"] = None
                            update_data["imageSize"] = None
                            update_data["imageMimeType"] = None
                    else:
                        update_data["imageUrl"] = None
                        update_data["imageR2Key"] = None
                        update_data["imageIv"] = None
                        update_data["imageSize"] = None
                        update_data["imageMimeType"] = None
                else:
                    update_data["imageUrl"] = None
                    update_data["imageR2Key"] = None
                    update_data["imageIv"] = None
                    update_data["imageSize"] = None
                    update_data["imageMimeType"] = None
            else:
                update_data["imageUrl"] = None
                update_data["imageR2Key"] = None
                update_data["imageIv"] = None
                update_data["imageSize"] = None
                update_data["imageMimeType"] = None
        else:
            # Fetch failed — clear image to avoid broken state
            update_data["imageUrl"] = None
            update_data["imageR2Key"] = None
            update_data["imageIv"] = None
            update_data["imageSize"] = None
            update_data["imageMimeType"] = None

    doc_ref.update(update_data)

    # Clean up old R2 image after successful update
    if old_image_r2_key and old_image_r2_key != update_data.get("imageR2Key"):
        try:
            delete_from_r2(old_image_r2_key)
        except Exception:
            pass

    return f"Moved drop '{d.get('name', drop_id)}' from '{src_name}' to '{tgt_name}'. Categories were preserved."


@mcp.tool()
def list_workspaces() -> str:
    """List all workspaces the user has access to, including their personal space.
    Returns personal space first, then all shared workspaces."""
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    workspaces = ["- Personal Space (your private drops, workspace_id=None)"]

    docs = db.collection("workspaces").where("members", "array_contains", user_id).stream()

    for doc in docs:
        d = doc.to_dict()
        role = "owner" if d.get("ownerId") == user_id else "member"
        workspaces.append(
            f"- {d.get('name', 'unnamed')} "
            f"(role={role}, "
            f"members={len(d.get('members', []))}, "
            f"invite={d.get('inviteCode', '?')}, "
            f"id={doc.id})"
        )

    return "\n".join(workspaces)


@mcp.tool()
def get_storage_stats() -> str:
    """Get storage stats across personal drops and all workspace drops the user has access to.
    Password drops are counted but content is not shown. Includes per-workspace breakdown."""
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    total_drops = 0
    total_size = 0
    file_count = 0
    text_count = 0
    text_with_image_count = 0
    encrypted_count = 0
    password_count = 0
    personal_count = 0
    workspace_counts: dict[str, int] = {}  # workspace_id -> count

    for doc in _get_all_accessible_drops(user_id):
        d = doc.to_dict()
        total_drops += 1
        total_size += d.get("fileSize", 0) or 0
        # Count image attachment storage for text drops
        if d.get("imageR2Key"):
            total_size += d.get("imageSize", 0) or 0
            text_with_image_count += 1
        if d.get("type") == "file":
            file_count += 1
        else:
            text_count += 1
        if d.get("encrypted"):
            encrypted_count += 1
        if _is_password_drop(d):
            password_count += 1

        ws_id = d.get("workspaceId")
        if ws_id:
            workspace_counts[ws_id] = workspace_counts.get(ws_id, 0) + 1
        else:
            personal_count += 1

    # Build per-workspace breakdown with names
    breakdown_lines = [f"  Personal: {personal_count}"]
    for ws_id, count in workspace_counts.items():
        ws_doc = db.collection("workspaces").document(ws_id).get()
        ws_name = ws_doc.to_dict().get("name", ws_id) if ws_doc.exists else ws_id
        breakdown_lines.append(f"  {ws_name}: {count}")

    return (
        f"Total drops: {total_drops}\n"
        f"Files: {file_count} | Text: {text_count} ({text_with_image_count} with images)\n"
        f"Encrypted: {encrypted_count}\n"
        f"Password-protected: {password_count} (hidden from AI)\n"
        f"Total size: {total_size / (1024*1024):.2f} MB\n"
        f"Breakdown:\n" + "\n".join(breakdown_lines) + "\n"
        f"Capacity: {total_drops}/200 drops"
    )


@mcp.tool()
def create_drop(
    name: str,
    content: str,
    workspace_id: str | None = None,
    categories: str | None = None,
    expiration: str = "2h",
) -> str:
    """Create a new text drop. The content will be encrypted automatically.
    Cannot create drops in the 'password' category.
    Args:
        name: Title for the drop.
        content: Text content for the drop.
        workspace_id: Optional workspace ID. If provided, creates in that workspace.
        categories: Comma-separated list of up to 3 categories (e.g. 'anime,notes'). Cannot include 'password'.
        expiration: When the drop expires. Options: '1h', '2h', '6h', '24h', 'forever'. Default: '2h'.
    Returns confirmation with the drop ID or an error message.
    """
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    # Handle case where model passes "None" as a string
    if workspace_id and workspace_id.lower() == "none":
        workspace_id = None

    # Authorization: if a workspace was specified, the caller must be a member
    # (Admin SDK bypasses firestore.rules, so enforce workspace membership here).
    # Personal drops (workspace_id None) are created under the caller's own userId.
    if not _is_workspace_member(user_id, workspace_id):
        return ACCESS_DENIED_WORKSPACE

    # Parse categories from comma-separated string
    category_list = []
    if categories:
        category_list = [c.strip() for c in categories.split(",") if c.strip()]
        if len(category_list) > 3:
            category_list = category_list[:3]
        for cat in category_list:
            if cat.lower() == "password":
                return PASSWORD_DENIED

    # Check drop limit (max 200)
    existing = list(db.collection("drops").where("userId", "==", user_id).limit(201).stream())
    if len(existing) >= 200:
        return "Cannot create drop — you've reached the 200 drop limit. Delete some drops first."

    # Calculate expiration
    valid_expirations = ("1h", "2h", "6h", "24h", "forever")
    if expiration not in valid_expirations:
        expiration = "2h"

    now = datetime.now(timezone.utc)
    if expiration == "forever":
        expires_at = None
    else:
        hours = int(expiration.replace("h", ""))
        expires_at = now + timedelta(hours=hours)

    # Resolve categories — auto-create if they don't exist
    resolved_categories: list[str] = []
    if category_list:
        cat_docs = list(db.collection("categories").where("workspaceId", "==", workspace_id).limit(100).stream())
        existing_names = {doc.to_dict().get("name", "").lower(): doc.to_dict().get("name") for doc in cat_docs}

        for cat in category_list:
            cat_stripped = cat.strip()
            cat_lower = cat_stripped.lower()
            if not cat_lower:
                continue
            if cat_lower in BUILT_IN_CATEGORIES:
                resolved_categories.append(cat_lower)
            elif cat_lower in existing_names:
                resolved_categories.append(existing_names[cat_lower])
            else:
                # Create new category
                db.collection("categories").add({
                    "name": cat_lower,
                    "workspaceId": workspace_id,
                    "createdBy": user_id,
                    "createdAt": firestore.SERVER_TIMESTAMP,
                })
                resolved_categories.append(cat_lower)

    # Encrypt content
    encrypted_fields = encrypt_drop_content(user_id, content, workspace_id)
    if not encrypted_fields:
        return "Failed to encrypt drop content. The user may not have encryption keys set up."

    # Build Firestore document
    doc_data: dict = {
        "userId": user_id,
        "type": "text",
        "name": name,
        "content": encrypted_fields["content"],
        "createdAt": firestore.SERVER_TIMESTAMP,
        "expiresAt": expires_at,
        "expirationOption": expiration,
        "workspaceId": workspace_id,
        "categories": resolved_categories if resolved_categories else [],
        "category": resolved_categories[0] if resolved_categories else None,  # Keep legacy field for backward compat
    }

    # Add encryption fields
    doc_data["encrypted"] = True
    if "iv" in encrypted_fields:
        doc_data["iv"] = encrypted_fields["iv"]
    if "encryptedDEK" in encrypted_fields:
        doc_data["encryptedDEK"] = encrypted_fields["encryptedDEK"]

    # Write to Firestore
    doc_ref = db.collection("drops").add(doc_data)

    return (
        f"Created drop '{name}' (id={doc_ref[1].id})\n"
        f"Type: text | Categories: {', '.join(resolved_categories) if resolved_categories else 'none'} | Expires: {expiration}\n"
        f"Workspace: {workspace_id or 'personal'}"
    )


def _create_workspace_key(workspace_id: str) -> bool:
    """Generate and store a workspace encryption key. Mirrors frontend createWorkspaceKey."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        # Generate random 32-byte secret (hex string like frontend)
        secret = secrets.token_hex(32)
        # Derive AES key from secret (first 32 bytes, same as frontend)
        secret_bytes = secret.encode("utf-8")[:32].ljust(32, b"\x00")

        # Generate random workspace AES key
        workspace_key = os.urandom(32)

        # Encrypt workspace key with secret
        iv = os.urandom(12)
        encrypted_key = AESGCM(secret_bytes).encrypt(
            iv,
            b64e(workspace_key).encode(),
            None,
        )

        db.collection("workspaceKeys").document(workspace_id).set({
            "workspaceId": workspace_id,
            "encryptedKey": b64e(encrypted_key),
            "iv": b64e(iv),
            "keySecret": secret,
            "createdAt": firestore.SERVER_TIMESTAMP,
        })
        return True
    except Exception as e:
        print(f"Error creating workspace key: {e}")
        return False


def _generate_invite_code() -> str:
    """Generate a random 6-character invite code (uppercase + digits)."""
    import string
    chars = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(6))


@mcp.tool()
def create_workspace(name: str) -> str:
    """Create a new workspace. The creator becomes the owner.
    A workspace encryption key and invite code are generated automatically.
    Args:
        name: Name for the workspace.
    Returns confirmation with workspace ID and invite code, or an error message.
    """
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    if not name.strip():
        return "Workspace name cannot be empty."

    # Create workspace document
    invite_code = _generate_invite_code()
    doc_ref = db.collection("workspaces").add({
        "name": name.strip(),
        "ownerId": user_id,
        "members": [user_id],
        "inviteCode": invite_code,
        "createdAt": firestore.SERVER_TIMESTAMP,
    })

    workspace_id = doc_ref[1].id

    # Create workspace encryption key
    if not _create_workspace_key(workspace_id):
        # Clean up workspace if key creation fails
        db.collection("workspaces").document(workspace_id).delete()
        return "Failed to create workspace encryption key. Please try again."

    return (
        f"Created workspace '{name.strip()}' (id={workspace_id})\n"
        f"Invite code: {invite_code}\n"
        f"You are the owner. Share the invite code to let others join."
    )


@mcp.tool()
def join_workspace(invite_code: str) -> str:
    """Join a workspace using an invite code.
    Returns the workspace details or an error if the code is invalid or you're already a member.
    """
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    invite_code = invite_code.strip().upper()
    if not invite_code:
        return "Invite code cannot be empty."

    # Find workspace by invite code
    docs = list(db.collection("workspaces").where("inviteCode", "==", invite_code).limit(1).stream())
    if not docs:
        return "Invalid invite code. Please check the code and try again."

    ws_doc = docs[0]
    ws_data = ws_doc.to_dict()

    # Check if already a member
    members = ws_data.get("members", [])
    if user_id in members:
        return f"You're already a member of '{ws_data.get('name', 'unnamed')}' workspace."

    # Add user to members
    updated_members = members + [user_id]
    db.collection("workspaces").document(ws_doc.id).update({
        "members": updated_members
    })

    return (
        f"Joined workspace '{ws_data.get('name', 'unnamed')}' (id={ws_doc.id}).\n"
        f"Members: {len(updated_members)} | Owner: {ws_data.get('ownerId', '?')}"
    )


@mcp.tool()
def list_categories(workspace_id: str | None = None) -> str:
    """List categories for a user, optionally filtered by workspace.
    Shows how many drops use each category so you can tell which are empty.
    - No workspace_id: returns personal categories only.
    - With workspace_id: returns categories for that workspace.
    Built-in categories (password, link) are always included.
    """
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    # Handle case where model passes "None" as a string
    if workspace_id and workspace_id.lower() == "none":
        workspace_id = None

    # Built-in categories
    built_in = ["password (hidden from AI)", "link"]

    if workspace_id:
        # Workspace categories — verify membership BEFORE reading (Admin SDK
        # bypasses firestore.rules, so enforce workspace access here).
        if not _is_workspace_member(user_id, workspace_id):
            return ACCESS_DENIED_WORKSPACE
        docs = db.collection("categories").where("workspaceId", "==", workspace_id).stream()
        ws_docs = db.collection("workspaces").document(workspace_id).get()
        ws_name = ws_docs.to_dict().get("name", workspace_id) if ws_docs.exists else workspace_id
        header = f"Categories in '{ws_name}':"
    else:
        # Personal categories — filter by createdBy AND workspaceId == null
        docs = db.collection("categories").where("createdBy", "==", user_id).where("workspaceId", "==", None).stream()
        header = "Personal categories:"

    categories = []
    for doc in docs:
        d = doc.to_dict()
        name = d.get("name", "")
        if name.lower() not in BUILT_IN_CATEGORIES:
            # Count drops using this category (check both array 'categories' and legacy 'category' fields)
            cat_lower = name.lower()
            if workspace_id:
                drops_arr = list(db.collection("drops").where("workspaceId", "==", workspace_id).where("categories", "array_contains", name).limit(201).stream())
                drops_str = list(db.collection("drops").where("workspaceId", "==", workspace_id).where("category", "==", name).limit(201).stream())
            else:
                drops_arr = list(db.collection("drops").where("userId", "==", user_id).where("workspaceId", "==", None).where("categories", "array_contains", name).limit(201).stream())
                drops_str = list(db.collection("drops").where("userId", "==", user_id).where("workspaceId", "==", None).where("category", "==", name).limit(201).stream())
            # Deduplicate by doc id
            all_ids = set()
            for dd in drops_arr:
                all_ids.add(dd.id)
            for dd in drops_str:
                all_ids.add(dd.id)
            usage = len(all_ids)
            categories.append(f"- {name} ({usage} drop{'s' if usage != 1 else ''}, id={doc.id})")

    if not categories and workspace_id:
        return f"{header}\n  (none — built-in: {', '.join(built_in)})"
    if not categories:
        return f"{header}\n  (none — built-in: {', '.join(built_in)})"

    return f"{header}\n{chr(10).join(categories)}\n  Built-in: {', '.join(built_in)}"


@mcp.tool()
def delete_category(category_id: str) -> str:
    """Delete a category by its ID.
    The category must belong to you (personal) or be in a workspace you're a member of.
    Built-in categories (password, link) cannot be deleted.
    """
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    doc_ref = db.collection("categories").document(category_id)
    doc = doc_ref.get()

    if not doc.exists:
        return f"Category '{category_id}' not found."

    d = doc.to_dict()
    name = d.get("name", "")

    # Block built-in categories
    if name.lower() in BUILT_IN_CATEGORIES:
        return f"Cannot delete the built-in '{name}' category."

    ws_id = d.get("workspaceId")
    created_by = d.get("createdBy")

    # Access control
    if ws_id:
        # Workspace category — verify membership
        if not _is_workspace_member(user_id, ws_id):
            return ACCESS_DENIED_WORKSPACE
    else:
        # Personal category — must be creator
        if created_by != user_id:
            return "Access denied — you can only delete your own categories."

    doc_ref.delete()
    return f"Deleted category '{name}'."


@mcp.tool()
def update_drop(
    drop_id: str,
    name: str | None = None,
    content: str | None = None,
    categories: str | None = None,
    expiration: str | None = None,
) -> str:
    """Update an existing text drop. Can update name, content, categories, and/or expiration.
    - For personal drops: content updates trigger re-encryption with a new DEK.
    - For workspace drops: content updates re-encrypt with the workspace key.
    - Password-category drops cannot be updated.
    - Supports up to 3 categories per drop (comma-separated).
    Args:
        drop_id: ID of the drop to update.
        name: New name for the drop (optional).
        content: New text content (optional, triggers re-encryption).
        categories: Comma-separated list of up to 3 category names (e.g. 'link,anime'). Pass '' to remove all.
        expiration: New expiration: '1h', '2h', '6h', '24h', 'forever' (optional).
    """
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    doc_ref = db.collection("drops").document(drop_id)
    doc = doc_ref.get()

    if not doc.exists:
        return f"Drop {drop_id} not found."

    d = doc.to_dict()

    # Only text drops can be updated
    if d.get("type") != "text":
        return "Only text drops can be updated through the assistant."

    # Access control
    ws_id = d.get("workspaceId")
    if ws_id:
        if not _is_workspace_member(user_id, ws_id):
            return ACCESS_DENIED_WORKSPACE
    else:
        if d.get("userId") != user_id:
            return "Access denied — you can only update your own drops."

    # Block password drops
    if _is_password_drop(d):
        return PASSWORD_DENIED

    update_data: dict = {}

    # --- Metadata updates ---
    if name is not None:
        if not name.strip():
            return "Drop name cannot be empty."
        update_data["name"] = name.strip()

    if categories is not None:
        # Parse comma-separated categories
        category_list = [c.strip() for c in categories.split(",") if c.strip()] if categories.strip() else []
        # Block password in categories
        for cat in category_list:
            if cat.lower() == "password":
                return PASSWORD_DENIED
        # Trim to max 3
        if len(category_list) > 3:
            category_list = category_list[:3]
        # Resolve category names
        resolved: list[str] = []
        if category_list:
            cat_docs = list(db.collection("categories")
                           .where("workspaceId", "==", ws_id)
                           .limit(100).stream())
            existing_names = {doc.to_dict().get("name", "").lower(): doc.to_dict().get("name") for doc in cat_docs}
            for cat in category_list:
                cat_stripped = cat.strip()
                cat_lower = cat_stripped.lower()
                if not cat_lower:
                    continue
                if cat_lower in BUILT_IN_CATEGORIES:
                    resolved.append(cat_lower)
                elif cat_lower in existing_names:
                    resolved.append(existing_names[cat_lower])
                else:
                    # Auto-create
                    db.collection("categories").add({
                        "name": cat_lower,
                        "workspaceId": ws_id,
                        "createdBy": user_id,
                        "createdAt": firestore.SERVER_TIMESTAMP,
                    })
                    resolved.append(cat_lower)
        update_data["categories"] = resolved
        update_data["category"] = None  # Clear legacy field

    if expiration is not None:
        valid_expirations = ("1h", "2h", "6h", "24h", "forever")
        if expiration not in valid_expirations:
            return f"Invalid expiration. Must be one of: {', '.join(valid_expirations)}"
        update_data["expirationOption"] = expiration
        if expiration == "forever":
            update_data["expiresAt"] = None
        else:
            hours = int(expiration.replace("h", ""))
            update_data["expiresAt"] = datetime.now(timezone.utc) + timedelta(hours=hours)

    # --- Content update (requires re-encryption) ---
    if content is not None:
        if ws_id:
            # Workspace drop — re-encrypt with workspace key
            encrypted = encrypt_workspace_drop(user_id, ws_id, content)
            if not encrypted:
                return "Failed to encrypt content. Workspace encryption key may not be set up."
            update_data.update(encrypted)
        else:
            # Personal drop — generate new DEK, re-encrypt
            encrypted = encrypt_personal_drop(user_id, content)
            if not encrypted:
                return "Failed to encrypt content. User encryption keys may not be set up."
            update_data.update(encrypted)

    # Nothing to update
    if not update_data:
        return "Nothing to update — no changes were specified."

    # Write to Firestore
    doc_ref.update(update_data)

    # Build confirmation message
    changes = []
    if "name" in update_data:
        changes.append(f"name -> '{update_data['name']}'")
    if "categories" in update_data:
        cats = ", ".join(update_data["categories"]) if update_data["categories"] else "none"
        changes.append(f"categories -> {cats}")
    if "expirationOption" in update_data:
        changes.append(f"expiration -> {update_data['expirationOption']}")
    if content is not None:
        changes.append("content re-encrypted")

    return f"Updated drop {drop_id}: {', '.join(changes)}."


# ── Run ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
