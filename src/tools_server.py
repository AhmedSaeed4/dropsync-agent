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
from decrypt import decrypt_drop_content, encrypt_drop_content, b64e
from datetime import datetime, timezone, timedelta
from firebase_admin import firestore
import secrets
import os

mcp = FastMCP("dropsync-tools")

PASSWORD_DENIED = "Access denied — this drop is in the 'password' category and cannot be accessed through the AI assistant. Use the DropSync app directly."

BUILT_IN_CATEGORIES = {"password", "link"}


# ── Helpers ─────────────────────────────────────────────────────

def _is_password_drop(d: dict) -> bool:
    """Check if a drop is in the password category."""
    cat = d.get("category") or ""
    return cat.lower() == "password"


def _format_drop(doc_id: str, d: dict, content_preview: str = "") -> str:
    """Format a drop for display."""
    return (
        f"- {d.get('name', 'untitled')} "
        f"(type={d.get('type', '?')}, "
        f"encrypted={d.get('encrypted', False)}, "
        f"category={d.get('category', 'none')}, "
        f"expires={d.get('expiresAt', 'never')}"
        f"{content_preview}, "
        f"id={doc_id})"
    )


# ── Tools ───────────────────────────────────────────────────────

@mcp.tool()
def list_drops(user_id: str, workspace_id: str | None = None) -> str:
    """List all drops for a user. Optionally filter by workspace.
    Returns drop names, types, sizes, expiration, category, and decrypted content preview.
    Password-category drops are excluded."""
    query = db.collection("drops").where("userId", "==", user_id)

    if workspace_id:
        query = query.where("workspaceId", "==", workspace_id)

    docs = query.stream()
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
def search_drops(user_id: str, query: str) -> str:
    """Search drops by name, text content, or category. Searches through decrypted content too.
    Password-category drops are excluded from results."""
    docs = db.collection("drops").where("userId", "==", user_id).stream()
    results = []
    query_lower = query.lower()

    for doc in docs:
        d = doc.to_dict()

        # Skip password-category drops
        if _is_password_drop(d):
            continue

        name = d.get("name", "").lower()
        category = (d.get("category") or "").lower()

        # Decrypt content to search through it
        decrypted_content = ""
        if d.get("type") == "text" and d.get("content"):
            decrypted = decrypt_drop_content(user_id, d)
            if decrypted:
                decrypted_content = decrypted.lower()

        if query_lower in name or query_lower in decrypted_content or query_lower in category:
            content_preview = f", content=\"{decrypted_content[:60]}\"" if decrypted_content else ""
            results.append(_format_drop(doc.id, d, content_preview))

    if not results:
        return f"No drops matching '{query}'."
    return "\n".join(results)


@mcp.tool()
def get_drop(user_id: str, drop_id: str) -> str:
    """Get full details for a specific drop, including decrypted content. Only returns drops owned by the user.
    Password-category drops cannot be accessed."""
    doc = db.collection("drops").document(drop_id).get()

    if not doc.exists:
        return f"Drop {drop_id} not found."

    d = doc.to_dict()
    if d.get("userId") != user_id:
        return "Access denied — this drop belongs to another user."

    if _is_password_drop(d):
        return PASSWORD_DENIED

    lines = [
        f"Name: {d.get('name', 'untitled')}",
        f"Type: {d.get('type', '?')}",
        f"Encrypted: {d.get('encrypted', False)}",
        f"Category: {d.get('category', 'none')}",
        f"Created: {d.get('createdAt', '?')}",
        f"Expires: {d.get('expiresAt', 'never')}",
        f"Size: {d.get('fileSize', 'N/A')} bytes",
    ]

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
def delete_drop(user_id: str, drop_id: str) -> str:
    """Delete a drop. Only the owner can delete their own drops.
    Password-category drops cannot be deleted through the agent."""
    doc_ref = db.collection("drops").document(drop_id)
    doc = doc_ref.get()

    if not doc.exists:
        return f"Drop {drop_id} not found."

    d = doc.to_dict()
    if d.get("userId") != user_id:
        return "Access denied — you can only delete your own drops."

    if _is_password_drop(d):
        return PASSWORD_DENIED

    doc_ref.delete()
    return f"Deleted drop '{d.get('name', drop_id)}'."


@mcp.tool()
def list_workspaces(user_id: str) -> str:
    """List all workspaces the user is a member of."""
    docs = db.collection("workspaces").where("members", "array_contains", user_id).stream()

    workspaces = []
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

    if not workspaces:
        return "No workspaces found."
    return "\n".join(workspaces)


@mcp.tool()
def get_storage_stats(user_id: str) -> str:
    """Get storage stats: total drops, total size, drops by type. Password drops are counted but content is not shown."""
    docs = db.collection("drops").where("userId", "==", user_id).stream()

    total_drops = 0
    total_size = 0
    file_count = 0
    text_count = 0
    encrypted_count = 0
    password_count = 0

    for doc in docs:
        d = doc.to_dict()
        total_drops += 1
        total_size += d.get("fileSize", 0) or 0
        if d.get("type") == "file":
            file_count += 1
        else:
            text_count += 1
        if d.get("encrypted"):
            encrypted_count += 1
        if _is_password_drop(d):
            password_count += 1

    return (
        f"Total drops: {total_drops}\n"
        f"Files: {file_count} | Text: {text_count}\n"
        f"Encrypted: {encrypted_count}\n"
        f"Password-protected: {password_count} (hidden from AI)\n"
        f"Total size: {total_size / (1024*1024):.2f} MB\n"
        f"Capacity: {total_drops}/50 drops"
    )


@mcp.tool()
def create_drop(
    user_id: str,
    name: str,
    content: str,
    workspace_id: str | None = None,
    category: str | None = None,
    expiration: str = "2h",
) -> str:
    """Create a new text drop. The content will be encrypted automatically.
    Cannot create drops in the 'password' category.
    Args:
        user_id: The user's ID (required).
        name: Title for the drop.
        content: Text content for the drop.
        workspace_id: Optional workspace ID. If provided, creates in that workspace.
        category: Optional category (e.g. 'anime', 'link'). Cannot be 'password'.
        expiration: When the drop expires. Options: '1h', '2h', '6h', '24h', 'forever'. Default: '2h'.
    Returns confirmation with the drop ID or an error message.
    """
    # Block password category
    if category and category.lower() == "password":
        return PASSWORD_DENIED

    # Check drop limit (max 50)
    existing = list(db.collection("drops").where("userId", "==", user_id).limit(51).stream())
    if len(existing) >= 50:
        return "Cannot create drop — you've reached the 50 drop limit. Delete some drops first."

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

    # Auto-create category if it doesn't exist (case-insensitive check)
    if category:
        category = category.strip()
        category_lower = category.lower()
        # Built-in categories don't need a Firestore document
        if category_lower not in BUILT_IN_CATEGORIES:
            cat_docs = list(db.collection("categories").where("workspaceId", "==", workspace_id).limit(100).stream())
            existing_cat = None
            for doc in cat_docs:
                doc_name = doc.to_dict().get("name", "")
                if doc_name.lower() == category_lower:
                    existing_cat = doc_name
                    break
            if existing_cat:
                category = existing_cat
            else:
                db.collection("categories").add({
                    "name": category,
                    "workspaceId": workspace_id,
                    "createdBy": user_id,
                    "createdAt": firestore.SERVER_TIMESTAMP,
                })
        else:
            category = category_lower

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
        "category": category or None,
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
        f"Type: text | Category: {category or 'none'} | Expires: {expiration}\n"
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
def create_workspace(user_id: str, name: str) -> str:
    """Create a new workspace. The creator becomes the owner.
    A workspace encryption key and invite code are generated automatically.
    Args:
        user_id: The user's ID (required).
        name: Name for the workspace.
    Returns confirmation with workspace ID and invite code, or an error message.
    """
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


# ── Run ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
