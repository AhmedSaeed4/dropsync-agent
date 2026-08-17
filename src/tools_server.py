"""
MCP server for DropSync Firestore tools.
Run as a standalone script — the agent connects via MCPServerStdio.
Supports decryption of both personal and workspace encrypted text drops.
Password-category drops are restricted — they cannot be listed, searched,
read, or deleted through the agent.
"""

import sys
import os
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

# Ensure this script's directory is on sys.path so imports work
# regardless of the working directory of the parent process
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

from mcp.server.fastmcp import FastMCP

from config import db
from authz import is_trusted_caller as _is_trusted_caller
from decrypt import DecryptionCache, decrypt_drop_content, encrypt_drop_content, b64e, b64d, encrypt_personal_drop, encrypt_workspace_drop, _get_workspace_key_data, _decrypt_with_workspace_key, _encrypt_with_workspace_key
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
import re

mcp = FastMCP("dropsync-tools")
logger = logging.getLogger(__name__)

PASSWORD_DENIED = "Access denied — this drop is in the 'password' category and cannot be accessed through the AI assistant. Use the DropSync app directly."

BUILT_IN_CATEGORIES = {"password", "link"}
SEARCH_TIME_BUDGET_SECONDS = 30.0
SEARCH_FIRESTORE_TIMEOUT_SECONDS = 5.0
SEARCH_RESULT_LIMIT = 10

# YouTube title lookups (keyless oEmbed). Fetched titles are cached per video
# in Firestore, so each video is requested from YouTube at most once, ever.
YOUTUBE_FETCH_CAP = 15          # max fresh YouTube fetches per tool call
YOUTUBE_FETCH_DELAY = 0.4       # seconds between fetches (browse, don't hammer)
YOUTUBE_REQUEST_TIMEOUT = 8.0   # seconds per HTTP request to YouTube
YOUTUBE_TIME_BUDGET = 40.0      # whole-call budget (the MCP layer kills at 60s)
YOUTUBE_DESC_PREVIEW = 300      # description preview chars (dormant until a key is set)
YOUTUBE_INPUT_LIMIT = 50        # max links processed per call
YOUTUBE_CACHE_COLLECTION = "youtubeTitles"


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


def _normalize_categories(d: dict) -> list[str]:
    """Return canonical and legacy categories in stable, de-duplicated order."""
    if not isinstance(d, dict):
        return []

    values = d.get("categories") if isinstance(d.get("categories"), list) else []
    legacy = d.get("category")
    if isinstance(legacy, str):
        values = [*values, legacy]

    categories = []
    seen = set()
    for value in values:
        if not isinstance(value, str):
            continue
        category = value.strip()
        key = category.lower()
        if category and key not in seen:
            seen.add(key)
            categories.append(category)
    return categories


def _is_expired_drop(d: dict, now: datetime) -> bool:
    """Return True for drops whose Firestore expiry has passed."""
    expires_at = d.get("expiresAt") if isinstance(d, dict) else None
    if not isinstance(expires_at, datetime):
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= now


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


def _resolve_reminder(
    reminder: str | None,
    expires_at: datetime | None,
    user_id: str,
    now: datetime,
) -> dict | str:
    """Parse the `reminder` tool param into the 3-field Firestore patch the frontend writes
    (TextModal.tsx:235-240). PURE: no I/O, no clock read. Single source of truth for
    create_drop and update_drop so the offset math, the cap-vs-expiry rule, and the
    reminderSetByUid stamping cannot drift between call sites.

    Returns:
      - {} for SKIP (reminder is None) — caller's dict.update({}) is a no-op.
      - ON patch {reminderAt:<tz-aware UTC dt>, reminderSetByUid:user_id, reminderDismissedBy:None}.
      - OFF patch {reminderAt:None, reminderSetByUid:None, reminderDismissedBy:None}
        for off/none/clear/null/''.
      - str for ERROR (unparseable, non-positive offset, malformed expires_at, or at > expires_at).
    `expires_at` None = forever = no cap. `user_id` = trusted _verified_uid(). `now` passed in.
    """
    # 1. SKIP — param omitted.
    if reminder is None:
        return {}
    # 2/3. OFF — explicit clear (also catches literal "None"/"Null").
    text = reminder.strip().lower()
    if text in {"", "off", "none", "clear", "null"}:
        return {"reminderAt": None, "reminderSetByUid": None, "reminderDismissedBy": None}
    # 4. Strict compact grammar <number><unit>, unit in {m,h,d}; decimals allowed.
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(m|h|d)", text)
    if not m:
        return ("Could not parse the reminder. Use a compact duration like '15m', '30m', "
                "'1h', '2h', '3h', or '1d', or pass 'off' to clear.")
    # 5/6. Offset; non-positive -> reject (useReminder.ts:124).
    count = float(m.group(1)); unit = m.group(2)
    offset_seconds = count * {"m": 60, "h": 3600, "d": 86400}[unit]
    if offset_seconds <= 0:
        return "Enter a reminder time in the future."
    # 7. Fire time (tz-aware UTC because now is).
    at = now + timedelta(seconds=offset_seconds)
    # 8. Defensive: malformed expires_at must NOT raise TypeError -> 500. Normalize tz-naive to
    #    UTC; reject non-datetime (fails closed, no write).
    if expires_at is not None:
        if not isinstance(expires_at, datetime):
            return "Could not validate the reminder against this drop's expiry. Use the DropSync app."
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    # 9. Cap = STRICT `>` to EXACTLY match frontend (useReminder.ts:133). at==expiry allowed.
    if expires_at is not None and at > expires_at:
        return "Reminder must be before the drop expires. Use a shorter reminder or a longer expiration."
    # 10. ON — uid stamped HERE from the trusted caller (no model channel).
    return {"reminderAt": at, "reminderSetByUid": user_id, "reminderDismissedBy": None}


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


def _get_workspace_name(
    ws_id: str,
    workspace_name_cache: dict[str, str] | None = None,
    timeout: float | None = None,
) -> str:
    """Get workspace name from ID. Returns the ID if not found."""
    if workspace_name_cache is not None and ws_id in workspace_name_cache:
        return workspace_name_cache[ws_id]
    get_kwargs = {"timeout": timeout} if timeout is not None else {}
    try:
        ws = db.collection("workspaces").document(ws_id).get(**get_kwargs)
        name = ws.to_dict().get("name", ws_id) if ws.exists else ws_id
    except Exception as exc:
        logger.warning("Workspace name lookup failed for %s: %s", ws_id, exc)
        name = ws_id
    if workspace_name_cache is not None:
        workspace_name_cache[ws_id] = name
    return name


def _format_drop(
    doc_id: str,
    d: dict,
    content_preview: str = "",
    workspace_name_cache: dict[str, str] | None = None,
    timeout: float | None = None,
) -> str:
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
    ws_name = _get_workspace_name(ws_id, workspace_name_cache, timeout) if ws_id else None
    ws_info = f"workspace={ws_name}({ws_id})" if ws_id else "workspace=Personal"
    categories = ", ".join(_normalize_categories(d)) or "none"
    return (
        f"- {d.get('name', 'untitled')} "
        f"(type={d.get('type', '?')}, "
        f"encrypted={d.get('encrypted', False)}, "
        f"category={categories}, "
        f"expires={d.get('expiresAt', 'never')}"
        f"{content_preview}{image_info}, "
        f"workspace_id={ws_id or 'null'}, "
        f"{ws_info}, "
        f"id={doc_id})"
    )


def _get_search_timeout(deadline: float) -> float | None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    return min(SEARCH_FIRESTORE_TIMEOUT_SECONDS, remaining)


def _stream_search_docs(query, deadline: float, label: str) -> tuple[list, bool]:
    """Read all available documents until the search deadline is reached."""
    timeout = _get_search_timeout(deadline)
    if timeout is None:
        return [], True

    docs = []
    try:
        for doc in query.stream(timeout=timeout):
            if time.monotonic() >= deadline:
                return docs, True
            docs.append(doc)
        return docs, False
    except Exception as exc:
        logger.warning("Search query failed for %s: %s", label, exc)
        return docs, True


def _get_user_workspace_ids(user_id: str, deadline: float) -> tuple[list[str], bool]:
    """Get IDs of all workspaces the user is a member of."""
    timeout = _get_search_timeout(deadline)
    if timeout is None:
        return [], True
    try:
        docs = db.collection("workspaces").where("members", "array_contains", user_id).stream(timeout=timeout)
        return [doc.id for doc in docs], False
    except Exception as exc:
        logger.warning("Workspace lookup failed during search: %s", exc)
        return [], True


def _get_all_accessible_drops(
    user_id: str,
    deadline: float,
) -> tuple[list, bool]:
    """Get all drops a user can access: personal drops + drops from all joined workspaces.
    Deduplicates by document ID and stops only when the search deadline is reached."""
    seen_ids = set()
    all_docs = []
    incomplete = False

    def add_query(query, label: str) -> None:
        nonlocal incomplete
        docs, query_incomplete = _stream_search_docs(query, deadline, label)
        incomplete = incomplete or query_incomplete
        for doc in docs:
            if doc.id not in seen_ids:
                seen_ids.add(doc.id)
                all_docs.append(doc)

    # 1. Personal drops (userId == me AND workspaceId == null)
    add_query(
        db.collection("drops").where("userId", "==", user_id).where("workspaceId", "==", None),
        "personal drops",
    )

    if time.monotonic() >= deadline:
        return all_docs, True

    # 2. Workspace drops — no userId filter, all members see all drops
    workspace_ids, workspace_lookup_incomplete = _get_user_workspace_ids(user_id, deadline)
    incomplete = incomplete or workspace_lookup_incomplete
    for ws_id in workspace_ids:
        if time.monotonic() >= deadline:
            incomplete = True
            break
        add_query(
            db.collection("drops").where("workspaceId", "==", ws_id),
            f"workspace {ws_id}",
        )

    return all_docs, incomplete


# ── YouTube helpers ─────────────────────────────────────────────

_YOUTUBE_HOSTS = {
    "youtube.com", "www.youtube.com", "m.youtube.com",
    "music.youtube.com", "youtube-nocookie.com", "www.youtube-nocookie.com",
}


def _extract_youtube_video_id(text: str) -> str | None:
    """Parse one YouTube URL (or a bare 11-char video ID) into its video ID.

    Accepts watch?v=, youtu.be/, /shorts/, /live/, /embed/, and /v/ links with
    any extra params. Returns None for anything that isn't a YouTube video
    link — callers report those as skipped rather than guessing.
    """
    t = (text or "").strip()
    if not t:
        return None
    # Bare video ID (the model sometimes strips the URL down to just this)
    if re.fullmatch(r"[A-Za-z0-9_-]{11}", t):
        return t
    m = re.match(r"^(?:https?://)?([^/?#\s]+)", t, re.IGNORECASE)
    if not m:
        return None
    host = m.group(1).lower().split(":")[0]  # strip a port if present
    rest = t[m.end():]
    if host == "youtu.be":
        vid = re.search(r"/([A-Za-z0-9_-]{11})(?:[?&#/]|$)", rest)
        return vid.group(1) if vid else None
    if host in _YOUTUBE_HOSTS:
        vid = re.search(r"[?&]v=([A-Za-z0-9_-]{11})", rest)
        if vid:
            return vid.group(1)
        vid = re.search(r"/(?:shorts|live|embed|v)/([A-Za-z0-9_-]{11})", rest)
        return vid.group(1) if vid else None
    return None


def _fetch_youtube_title(video_id: str) -> tuple[str | None, str | None, str | None]:
    """Fetch a video's title + channel via YouTube's keyless oEmbed endpoint.

    Returns (title, channel, error). error is None on success. A video that
    oEmbed won't serve (private / deleted / age-restricted) returns a human-
    readable reason instead of raising — one bad link must not sink the batch.
    """
    oembed_url = "https://www.youtube.com/oembed?" + urllib.parse.urlencode(
        {"url": f"https://www.youtube.com/watch?v={video_id}", "format": "json"}
    )
    req = urllib.request.Request(
        oembed_url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; DropSync-Assistant/1.0)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=YOUTUBE_REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        title = data.get("title")
        if not (isinstance(title, str) and title):
            return None, None, "no title returned for this video"
        return title, data.get("author_name"), None
    except urllib.error.HTTPError as exc:
        # 400/401/403/404 from oEmbed = private, deleted, or restricted video.
        # 429 = YouTube asked us to slow down (caller backs off, tries later).
        if exc.code in (400, 401, 403, 404):
            return None, None, "unavailable (private, deleted, or restricted video)"
        if exc.code == 429:
            return None, None, "YouTube asked us to slow down — try again in a minute"
        return None, None, f"YouTube returned HTTP {exc.code}"
    except Exception:
        return None, None, "network error reaching YouTube"


def _fetch_youtube_description(video_id: str) -> str | None:
    """DORMANT unless YOUTUBE_API_KEY is set: fetch a short description preview
    via the YouTube Data API (1 quota unit per call). Returns None with no key
    or on any failure — title-only output stays valid either way. The key is
    intentionally NOT configured today; this path activates automatically the
    moment it appears in the environment (HF secret or local .env).
    """
    api_key = os.environ.get("YOUTUBE_API_KEY", "").strip()
    if not api_key:
        return None
    url = ("https://www.googleapis.com/youtube/v3/videos?part=snippet&"
           + urllib.parse.urlencode({"id": video_id, "key": api_key}))
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (compatible; DropSync-Assistant/1.0)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=YOUTUBE_REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        items = data.get("items") or []
        if not items:
            return None
        raw = items[0].get("snippet", {}).get("description") or ""
        preview = re.sub(r"\s+", " ", raw).strip()
        if len(preview) > YOUTUBE_DESC_PREVIEW:
            preview = preview[:YOUTUBE_DESC_PREVIEW].rsplit(" ", 1)[0] + "…"
        return preview or None
    except Exception:
        return None  # description is a bonus — never fail the title over it


_YOUTUBE_TOKEN_RE = re.compile(
    r"(?<![\w.\-/])(?:https?://)?(?:[\w-]+\.)*(?:youtube\.com|youtu\.be)/[^\s,;<>\"']+",
    re.IGNORECASE,
)


def _extract_youtube_ids_from_text(text: str) -> list[str]:
    """Pull every unique YouTube video ID out of free text, in order of appearance."""
    ids: list[str] = []
    seen: set[str] = set()
    for token in _YOUTUBE_TOKEN_RE.findall(text or ""):
        vid = _extract_youtube_video_id(token)
        if vid and vid not in seen:
            seen.add(vid)
            ids.append(vid)
    return ids


def _fetch_missing_titles(misses: list[str], deadline: float) -> tuple[dict[str, dict], int, bool, int]:
    """Fetch uncached video titles from YouTube — capped, paced, budget-bound.

    Shared by get_youtube_titles and find_video_drops. A 429 (slow down) stops
    the batch early. Successful fetches are cached in Firestore (description
    preview too, when the dormant key path is active); failures are NOT cached —
    an unavailable video may return later.

    Returns (results, fetched_count, throttled, pending_count) where results
    maps vid -> {title, channel, desc, status, error?} and status is one of:
    'fetched' | 'unavailable' | 'throttled' | 'pending' (not attempted this call).
    """
    results: dict[str, dict] = {}
    fetched = 0
    throttled = False
    for i, vid in enumerate(misses):
        if throttled or fetched >= YOUTUBE_FETCH_CAP or time.monotonic() >= deadline:
            for rest_vid in misses[i:]:
                results[rest_vid] = {
                    "title": None, "channel": None, "desc": None, "status": "pending",
                }
            break
        if fetched > 0:
            time.sleep(YOUTUBE_FETCH_DELAY)
        title, channel, error = _fetch_youtube_title(vid)
        fetched += 1
        if title is None:
            if error and "slow down" in error:
                throttled = True
            results[vid] = {
                "title": None, "channel": None, "desc": None,
                "status": "throttled" if throttled else "unavailable",
                "error": error,
            }
            continue
        # Dormant unless YOUTUBE_API_KEY is set — None today, zero cost.
        desc = _fetch_youtube_description(vid)
        results[vid] = {"title": title, "channel": channel, "desc": desc, "status": "fetched"}
        try:
            cache_doc = {
                "videoId": vid,
                "title": title,
                "author_name": channel if isinstance(channel, str) else None,
                "fetchedAt": firestore.SERVER_TIMESTAMP,
            }
            if desc:
                cache_doc["descriptionPreview"] = desc
            db.collection(YOUTUBE_CACHE_COLLECTION).document(vid).set(cache_doc)
        except Exception:
            pass  # best-effort — the answer still returns, just isn't remembered
    pending = sum(1 for r in results.values() if r["status"] == "pending")
    return results, fetched, throttled, pending


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

    now = datetime.now(timezone.utc)
    decryption_cache = DecryptionCache(firestore_timeout=SEARCH_FIRESTORE_TIMEOUT_SECONDS)
    workspace_name_cache: dict[str, str] = {}
    drops = []
    file_count = 0
    for doc in docs:
        d = doc.to_dict()

        # Skip password-category drops
        if _is_password_drop(d):
            continue
        if _is_expired_drop(d, now):
            continue

        if d.get("type") == "file":
            file_count += 1

        # Decrypt content for preview
        content_preview = ""
        if d.get("type") == "text" and d.get("content"):
            decrypted = decrypt_drop_content(user_id, d, cache=decryption_cache)
            if decrypted:
                content_preview = f", content=\"{decrypted[:60]}\""

        drops.append(
            _format_drop(
                doc.id,
                d,
                content_preview,
                workspace_name_cache,
                timeout=SEARCH_FIRESTORE_TIMEOUT_SECONDS,
            )
        )

    if not drops:
        return "No drops found."

    # Count header FIRST: models miscount 50+ line lists (wrong drop counts on
    # big workspaces) — with the total up top the model reads it instead of
    # counting lines itself. The exclusion note explains any gap vs the app UI.
    text_count = len(drops) - file_count
    if workspace_id and workspace_id.lower() != "none":
        ws_name = _get_workspace_name(workspace_id, workspace_name_cache)
        header = (
            f"{len(drops)} drops in workspace \"{ws_name}\" "
            f"({text_count} text, {file_count} file; "
            f"password and expired drops not included):"
        )
    else:
        header = (
            f"{len(drops)} personal drops "
            f"({text_count} text, {file_count} file; "
            f"password and expired drops not included):"
        )
    return header + "\n" + "\n".join(drops)


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
    deadline = time.monotonic() + SEARCH_TIME_BUDGET_SECONDS
    now = datetime.now(timezone.utc)
    decryption_cache = DecryptionCache(firestore_timeout=SEARCH_FIRESTORE_TIMEOUT_SECONDS)
    workspace_name_cache: dict[str, str] = {}
    documents, incomplete = _get_all_accessible_drops(user_id, deadline)

    for doc in documents:
        if time.monotonic() >= deadline:
            incomplete = True
            break
        d = doc.to_dict()

        if _is_expired_drop(d, now):
            continue

        # Skip password-category drops
        if _is_password_drop(d):
            continue

        name = d.get("name", "")
        category = ", ".join(_normalize_categories(d))

        # Decrypt content to search through it
        decrypted_content = ""
        if d.get("type") == "text" and d.get("content"):
            decryption_cache.firestore_timeout = _get_search_timeout(deadline)
            if decryption_cache.firestore_timeout is None:
                incomplete = True
                break
            decrypted = decrypt_drop_content(user_id, d, cache=decryption_cache)
            if decrypted:
                decrypted_content = decrypted

        score = _score_query(query_lower, name, category, decrypted_content)

        # Minimum threshold: at least one token must match something
        if score > 0.05:
            format_timeout = _get_search_timeout(deadline)
            if format_timeout is None:
                incomplete = True
                break
            content_preview = f', content="{decrypted_content[:60]}"' if decrypted_content else ""
            scored_results.append((
                score,
                _format_drop(
                    doc.id,
                    d,
                    content_preview,
                    workspace_name_cache,
                    timeout=format_timeout,
                ),
            ))

    if not scored_results:
        if incomplete:
            return f"Search incomplete for '{query}'. Try a narrower query."
        return f"No drops matching '{query}'. Try listing your drops to see what's available."

    # Sort by score descending, return top 10
    scored_results.sort(key=lambda x: -x[0])
    top_results = scored_results[:SEARCH_RESULT_LIMIT]

    output_parts = []
    if incomplete:
        output_parts.append(
            f"Search incomplete for '{query}'. Showing matches found before the search limit."
        )
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
        f"Category: {', '.join(_normalize_categories(d)) or 'none'}",
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

    # Trusted-tier gate. move_drop does NOT change expiration (it cannot MINT forever — its
    # update_data has no expirationOption/expiresAt key), but it PRESERVES it: relocating a forever
    # source is a forever-write that firestore.rules:291 would block for a non-trusted member on a
    # client write. The Admin SDK bypasses that, so enforce here. REJECT (not downgrade): silently
    # shortening a trusted owner's drop to 24h on move would be data loss. The trusted owner can
    # still move their own forever drop. Placed before any decrypt/re-encrypt/write (~589/~636/~703).
    if (d.get("expirationOption") == "forever" or d.get("expiresAt") is None) \
            and not _is_trusted_caller(user_id):
        return ("This drop never expires, so only trusted users can move it. "
                "Use the DropSync app.")

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
def copy_drop(drop_id: str, target_workspace_id: str) -> str:
    """Duplicate a text drop into a different workspace, leaving the original and its attached
    image in place. Workspace-to-workspace only. Content + any attached image are re-encrypted
    end-to-end for the target. Categories preserved (missing ones auto-created in the target).
    Contrast with move_drop (RELOCATES); copy_drop DUPLICATES (original stays).
    Args:
        drop_id: ID of the drop to copy.
        target_workspace_id: ID of the target workspace (must differ from source).
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

    if not source_ws:
        return "Cannot copy personal drops via chat. Use the DropSync app."
    if not target_workspace_id or target_workspace_id.lower() == "none":
        return "Cannot copy to personal via chat. Use the DropSync app."
    if source_ws == target_workspace_id:
        return "Drop is already in that workspace. Use the DropSync app to duplicate within the same workspace."
    if not _is_workspace_member(user_id, source_ws):
        return "Access denied — you're not a member of the source workspace."
    if not _is_workspace_member(user_id, target_workspace_id):
        return "Access denied — you're not a member of the target workspace."
    if _is_password_drop(d):
        return PASSWORD_DENIED
    if d.get("type") != "text":
        return "Only text drops can be copied via chat. Use the app to copy file drops."

    src_name = _get_workspace_name(source_ws)
    tgt_name = _get_workspace_name(target_workspace_id)

    decrypted_content = decrypt_drop_content(user_id, d)
    if not decrypted_content:
        return "Failed to decrypt drop content. Cannot copy."
    encrypted = encrypt_workspace_drop(user_id, target_workspace_id, decrypted_content)
    if not encrypted:
        return "Failed to re-encrypt content for target workspace."

    # Category preserve + auto-create in TARGET (mirrors move_drop 556-594).
    source_categories = d.get("categories") or ([d.get("category")] if d.get("category") else [])
    if source_categories:
        resolved_categories = []
        custom_categories = []
        for cat_name in source_categories:
            if cat_name.lower().strip() in BUILT_IN_CATEGORIES:
                resolved_categories.append(cat_name.lower().strip())
            else:
                custom_categories.append(cat_name)
        if custom_categories:
            cat_docs = list(db.collection("categories")
                            .where("workspaceId", "==", target_workspace_id).limit(100).stream())
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
                        "name": name_lower, "workspaceId": target_workspace_id,
                        "createdBy": user_id, "createdAt": firestore.SERVER_TIMESTAMP,
                    })
                    existing_categories[name_lower] = name_lower
                    resolved_categories.append(name_lower)
    else:
        resolved_categories = []

    # Expiration: inherit option, RECOMPUTE expiresAt from now (fresh lifetime; never born expired).
    opt = d.get("expirationOption")
    if opt not in ("1h", "2h", "6h", "24h", "forever"):
        opt = "2h"
    # Trusted-tier gate (the Admin SDK bypasses firestore.rules:276). The frontend copy path
    # DOWNGRADES a forever source to 24h for non-trusted users (drops.ts:1645-1652) rather than
    # rejecting — mirror that exactly so a standard copier still gets a legal 24h copy. The
    # expires_at recompute on the next line then uses the downgraded opt. (Safe even though the
    # category auto-create at ~787-790 ran earlier: copy DOWNGRADES, it never short-circuits/returns,
    # so those categories belong to the successful 24h copy — no orphans.)
    if opt == "forever" and not _is_trusted_caller(user_id):
        opt = "24h"
    now = datetime.now(timezone.utc)
    expires_at = None if opt == "forever" else now + timedelta(hours=int(opt.replace("h", "")))

    # Image re-encryption into a NEW R2 object. On ANY step failure image_fields stays {} ->
    # copy created text-only (absent image keys == no image). Source R2 image NEVER deleted.
    image_fields: dict = {}
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
                            image_fields = {
                                "imageUrl": upload_result["url"],
                                "imageR2Key": upload_result["key"],
                                "imageIv": re_encrypted["iv"],
                            }
                            if d.get("imageSize"):
                                image_fields["imageSize"] = d["imageSize"]
                            if d.get("imageMimeType"):
                                image_fields["imageMimeType"] = d["imageMimeType"]
    # (NO else branches writing None — absent == no image on a NEW doc.)

    new_doc: dict = {
        "userId": user_id,
        "type": "text",
        "name": d.get("name", drop_id),
        "content": encrypted["content"],
        "createdAt": firestore.SERVER_TIMESTAMP,
        "expiresAt": expires_at,
        "expirationOption": opt,
        "workspaceId": target_workspace_id,
        "categories": resolved_categories,
        "category": resolved_categories[0] if resolved_categories else None,
        "encrypted": True,
        "iv": encrypted["iv"],
        "encryptedDEK": None,
    }
    if image_fields:
        new_doc.update(image_fields)

    new_ref = db.collection("drops").add(new_doc)

    img_note = " Image was re-encrypted for the target workspace." if image_fields else ""
    return (
        f"Copied drop '{new_doc['name']}' (id={new_ref[1].id}) "
        f"from '{src_name}' to '{tgt_name}'. Categories were preserved. "
        f"Original left in place.{img_note}"
    )


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
    )


@mcp.tool()
def get_youtube_titles(urls: str) -> str:
    """Get the real titles and channel names of YouTube videos from links.
    Accepts any mix of YouTube URLs (watch, youtu.be, shorts, live, embed) or
    bare video IDs, separated by spaces, commas, or newlines.
    Titles are cached per video: known titles return instantly with zero
    requests to YouTube; only never-seen videos are fetched (max 15 per call,
    gently paced). If some videos were not fetched yet, call this tool again
    with the SAME links — already-fetched ones return from the cache instantly.
    Use this whenever a YouTube link matters. NEVER guess a video's title.
    """
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    raw_items = [s for s in re.split(r"[\s,]+", (urls or "").strip()) if s]
    if not raw_items:
        return "No links provided. Pass one or more YouTube links (space, comma, or newline separated)."
    over_limit = len(raw_items) - YOUTUBE_INPUT_LIMIT
    if over_limit > 0:
        raw_items = raw_items[:YOUTUBE_INPUT_LIMIT]

    # Parse + dedupe in input order; non-YouTube entries are reported, not guessed.
    ordered: list[str] = []
    seen: set[str] = set()
    not_youtube: list[str] = []
    for item in raw_items:
        vid = _extract_youtube_video_id(item)
        if vid is None:
            not_youtube.append(item)
            continue
        if vid not in seen:
            seen.add(vid)
            ordered.append(vid)

    if not ordered:
        shown = ", ".join(not_youtube[:10]) + ("…" if len(not_youtube) > 10 else "")
        return f"No YouTube links found in the input. Skipped: {shown}"

    deadline = time.monotonic() + YOUTUBE_TIME_BUDGET

    # 1. Cache first — a remembered title costs zero YouTube requests. The cache
    #    is shared across chats and users (keyed by video, not by drop), so a
    #    video is fetched from YouTube at most once, ever.
    results: dict[str, dict] = {}  # vid -> {title, channel, desc, error, cached}
    misses: list[str] = []
    for vid in ordered:
        try:
            doc = db.collection(YOUTUBE_CACHE_COLLECTION).document(vid).get(
                timeout=SEARCH_FIRESTORE_TIMEOUT_SECONDS
            )
        except Exception:
            doc = None
        d = (doc.to_dict() or {}) if (doc is not None and doc.exists) else {}
        if isinstance(d.get("title"), str) and d.get("title"):
            results[vid] = {
                "title": d["title"],
                "channel": d.get("author_name"),
                "desc": d.get("descriptionPreview"),
                "status": "memory",
            }
        else:
            misses.append(vid)

    # 2. Fetch only the misses — capped per call, paced, and budget-bound (the
    #    pacing/caching rules live in _fetch_missing_titles, shared with
    #    find_video_drops). Unfetched misses come back 'pending' so the model
    #    can simply call again with the same links.
    fetch_results, fetched, throttled, unattempted = _fetch_missing_titles(misses, deadline)
    results.update(fetch_results)

    # 3. Compose output — the tool computes the counts itself (models miscount
    #    long lists; never let the LLM count lines).
    ok = [vid for vid in ordered if results.get(vid, {}).get("title")]
    from_cache = sum(1 for vid in ok if results[vid]["status"] == "memory")
    lines = [
        f"Resolved {len(ok)} of {len(ordered)} YouTube links "
        f"({from_cache} from memory, {len(ok) - from_cache} fetched fresh):"
    ]
    for vid in ordered:
        r = results.get(vid)
        if r is None:
            continue
        if r["title"]:
            by = f" — by {r['channel']}" if r["channel"] else ""
            note = " (from memory)" if r["status"] == "memory" else ""
            lines.append(f"- \"{r['title']}\"{by} (id={vid}){note}")
            if r["desc"]:
                lines.append(f"  Description preview: {r['desc']}")
        else:
            lines.append(f"- {vid}: {r.get('error') or r['status']}")
    if not_youtube:
        shown = ", ".join(not_youtube[:10]) + ("…" if len(not_youtube) > 10 else "")
        lines.append(f"Skipped (not YouTube links): {shown}")
    if over_limit > 0:
        lines.append(f"Input truncated to the first {YOUTUBE_INPUT_LIMIT} links ({over_limit} more ignored).")
    if throttled:
        lines.append("YouTube asked us to slow down — wait a minute, then call again with the same links.")
    elif unattempted:
        lines.append(
            f"{unattempted} new video(s) not fetched yet (per-call limit) — "
            "call get_youtube_titles again with the same links; remembered ones return instantly."
        )
    return "\n".join(lines)


@mcp.tool()
def find_video_drops() -> str:
    """Find every accessible drop that contains a YouTube link, with each video's
    REAL title and which drop/workspace it lives in — the complete list in one call.
    Use this whenever the user asks about, describes, or wants to find a saved
    video (by exact title OR by concept): read the returned titles and match the
    user's words yourself. Titles are remembered per video, so repeat calls are
    instant. If some titles are listed as pending, call this tool again to fetch
    the rest. NEVER guess a video's title, and NEVER claim a video isn't saved
    without checking this list first.
    """
    user_id = _verified_uid()
    if not user_id:
        return _UID_DENIED

    deadline = time.monotonic() + SEARCH_TIME_BUDGET_SECONDS
    now = datetime.now(timezone.utc)
    decryption_cache = DecryptionCache(firestore_timeout=SEARCH_FIRESTORE_TIMEOUT_SECONDS)
    workspace_name_cache: dict[str, str] = {}

    # Personal drops + member workspaces ONLY — same access scope as search_drops
    # (_get_all_accessible_drops checks the members list of each workspace).
    documents, incomplete = _get_all_accessible_drops(user_id, deadline)

    video_ids: list[str] = []
    seen_ids: set[str] = set()
    drop_entries: list[tuple[str, dict, list[str]]] = []
    drops_scanned = 0
    for doc in documents:
        if time.monotonic() >= deadline:
            incomplete = True
            break
        d = doc.to_dict()
        drops_scanned += 1
        # Password drops are never decrypted; expired drops are gone.
        if _is_password_drop(d) or _is_expired_drop(d, now):
            continue
        text = ""
        if d.get("type") == "text" and d.get("content"):
            decryption_cache.firestore_timeout = _get_search_timeout(deadline)
            if decryption_cache.firestore_timeout is None:
                incomplete = True
                break
            decrypted = decrypt_drop_content(user_id, d, cache=decryption_cache)
            if decrypted:
                text = decrypted
        combined = " ".join(x for x in [(d.get("name") or ""), text] if x)
        ids_in_drop: list[str] = []
        for vid in _extract_youtube_ids_from_text(combined):
            if vid not in ids_in_drop:
                ids_in_drop.append(vid)
            if vid not in seen_ids:
                seen_ids.add(vid)
                video_ids.append(vid)
        if ids_in_drop:
            drop_entries.append((doc.id, d, ids_in_drop))

    if not drop_entries:
        note = " (scan hit the time limit — try again)" if incomplete else ""
        return f"None of the {drops_scanned} drops scanned contain YouTube links.{note}"

    # Resolve titles: drawer first (instant), then capped fresh fetches.
    title_map: dict[str, dict] = {}
    misses: list[str] = []
    for vid in video_ids:
        if time.monotonic() >= deadline:
            incomplete = True
            break
        try:
            cdoc = db.collection(YOUTUBE_CACHE_COLLECTION).document(vid).get(timeout=2.0)
        except Exception:
            cdoc = None
        cd = (cdoc.to_dict() or {}) if (cdoc is not None and cdoc.exists) else {}
        if isinstance(cd.get("title"), str) and cd.get("title"):
            title_map[vid] = {
                "title": cd["title"], "channel": cd.get("author_name"),
                "desc": cd.get("descriptionPreview"), "status": "memory",
            }
        else:
            misses.append(vid)

    fetch_results, _fetched, throttled, _pending = _fetch_missing_titles(misses, deadline)
    title_map.update(fetch_results)

    # Compose — computed counts first (never let the LLM count lines), then one
    # line per video pointing at the drop it lives in.
    from_cache = sum(1 for r in title_map.values() if r.get("status") == "memory" and r.get("title"))
    fresh = sum(1 for r in title_map.values() if r.get("status") == "fetched")
    lines = [
        f"Found {len(video_ids)} YouTube video(s) across {len(drop_entries)} drop(s) "
        f"— titles: {from_cache + fresh} known ({from_cache} from memory, {fresh} fetched fresh):"
    ]
    for doc_id, d, ids in drop_entries:
        ws_id = d.get("workspaceId")
        where = _get_workspace_name(ws_id, workspace_name_cache) if ws_id else "Personal"
        for vid in ids:
            r = title_map.get(vid) or {"status": "pending"}
            drop_label = f"drop \"{d.get('name', 'untitled')}\" ({where}, drop_id={doc_id})"
            if r.get("title"):
                by = f" — by {r['channel']}" if r.get("channel") else ""
                note = " (from memory)" if r.get("status") == "memory" else ""
                lines.append(f"- \"{r['title']}\"{by} → {drop_label}{note}")
            elif r.get("status") == "pending":
                lines.append(f"- [title not fetched yet] video {vid} → {drop_label}")
            else:
                reason = r.get("error") or r.get("status") or "unavailable"
                lines.append(f"- [title unavailable: {reason}] video {vid} → {drop_label}")

    pending_total = sum(1 for vid in video_ids if (title_map.get(vid) or {}).get("status") == "pending")
    if incomplete:
        lines.append("Note: the drop scan hit the time limit — some drops were not scanned; call again.")
    if throttled:
        lines.append("YouTube asked us to slow down — wait a minute, then call again to fetch remaining titles.")
    elif pending_total:
        lines.append(
            f"{pending_total} title(s) still pending (per-call fetch limit) — "
            "call find_video_drops again to fetch them."
        )
    return "\n".join(lines)


@mcp.tool()
def create_drop(
    name: str,
    content: str,
    workspace_id: str | None = None,
    categories: str | None = None,
    expiration: str = "2h",
    reminder: str | None = None,
) -> str:
    """Create a new text drop. The content will be encrypted automatically.
    Cannot create drops in the 'password' category.
    Args:
        name: Title for the drop.
        content: Text content for the drop.
        workspace_id: Optional workspace ID. If provided, creates in that workspace.
        categories: Comma-separated list of up to 3 categories (e.g. 'anime,notes'). Cannot include 'password'.
        expiration: When the drop expires. Options: '1h', '2h', '6h', '24h', 'forever'. Default: '2h'.
        reminder: Optional in-app reminder as '<number><unit>' (m=minutes, h=hours, d=days).
            Examples '15m','30m','1h','2h','3h','1d','90m','0.5d'. Decimals allowed. Omit/None
            for no reminder; 'off'/'none' to explicitly skip. Must land before expiry (rejected
            strictly after expiry; 'forever' has no cap). Text drops only.
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

    # Calculate expiration
    valid_expirations = ("1h", "2h", "6h", "24h", "forever")
    if expiration not in valid_expirations:
        expiration = "2h"

    # Trusted-tier gate (the Admin SDK bypasses firestore.rules:276, so this helper IS the
    # enforcement of (!isForeverWrite() || isTrusted()) for agent writes). Only the owner or a
    # trusted-tier user may create a never-expiring drop; everyone else picks a timed option.
    # Runs before ANY Firestore write (the only write is the add() at ~1067).
    if expiration == "forever" and not _is_trusted_caller(user_id):
        return ("Your account isn't trusted to create drops that never expire. "
                "Choose 1h, 2h, 6h, or 24h, or use the DropSync app to request trusted access.")

    now = datetime.now(timezone.utc)
    if expiration == "forever":
        expires_at = None
    else:
        hours = int(expiration.replace("h", ""))
        expires_at = now + timedelta(hours=hours)

    # Reminder (reuses the same `now` as expires_at — no skew).
    reminder_patch = _resolve_reminder(reminder, expires_at, user_id, now)
    if isinstance(reminder_patch, str):
        return reminder_patch

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

    # Add reminder ON patch (OFF/SKIP write nothing — no reminder keys on the doc).
    if reminder_patch and reminder_patch.get("reminderAt") is not None:
        doc_data.update(reminder_patch)

    # Write to Firestore
    doc_ref = db.collection("drops").add(doc_data)

    confirmation = (
        f"Created drop '{name}' (id={doc_ref[1].id})\n"
        f"Type: text | Categories: {', '.join(resolved_categories) if resolved_categories else 'none'} | Expires: {expiration}\n"
        f"Workspace: {workspace_id or 'personal'}"
    )
    if reminder_patch and reminder_patch.get("reminderAt") is not None:
        confirmation += f"\nReminder: set (fires ~{reminder_patch['reminderAt'].strftime('%Y-%m-%d %H:%M UTC')})"
    return confirmation


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
    reminder: str | None = None,
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
        reminder: Optional. Set/change a reminder with a compact duration ('15m','1h','1d',...).
            Pass 'off'/'none' to CLEAR. Omit (None) to leave UNCHANGED. Must land before expiry
            (rejected strictly after). Text drops only.
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

    if expiration is not None:
        valid_expirations = ("1h", "2h", "6h", "24h", "forever")
        if expiration not in valid_expirations:
            return f"Invalid expiration. Must be one of: {', '.join(valid_expirations)}"
        # Trusted-tier gate (the Admin SDK bypasses firestore.rules:291). Blocks a standard user
        # from upgrading a compliant timed drop to forever. Placed BEFORE the first Firestore write
        # in this tool (category auto-create ~1412) — same zero-orphan-write ordering the reminder
        # block uses (comment ~1373-1376).
        if expiration == "forever" and not _is_trusted_caller(user_id):
            return ("Your account isn't trusted to set a drop to never expire. "
                    "Choose 1h, 2h, 6h, or 24h.")
        update_data["expirationOption"] = expiration
        if expiration == "forever":
            update_data["expiresAt"] = None
        else:
            hours = int(expiration.replace("h", ""))
            update_data["expiresAt"] = datetime.now(timezone.utc) + timedelta(hours=hours)

    # Trusted-tier parity (rules:291): a non-trusted user may not edit an existing FOREVER drop
    # unless they also downgrade it to a timed expiry — the result drop would still be forever, and
    # firestore.rules:291 rejects that for a non-trusted member on a client write; the Admin SDK
    # bypasses it, so enforce here. (expiration=='forever' already rejected above; an explicit TIMED
    # expiration downgrades the result to non-forever and is ALLOWED; this only fires when the caller
    # did NOT pass expiration but the source is forever.) Placed before the first write (~1412).
    if expiration is None and not _is_trusted_caller(user_id) \
            and (d.get("expirationOption") == "forever" or d.get("expiresAt") is None):
        return ("This drop never expires, so only trusted users can edit it. "
                "Switch it to a timed expiry (1h/2h/6h/24h) to edit it, or use the DropSync app.")

    # Reminder: None=leave-unchanged; 'off'/'none'=CLEAR; duration=SET. Placed AFTER expiration
    # (so the cap uses the NEW expiresAt when both passed) and BEFORE the categories block (the
    # first Firestore write in this function — it auto-creates category docs), so an invalid /
    # unparseable / over-cap reminder returns with ZERO Firestore writes (no orphan category).
    if reminder is not None:
        effective_expires_at = update_data.get("expiresAt") if "expiresAt" in update_data else d.get("expiresAt")
        reminder_patch = _resolve_reminder(reminder, effective_expires_at, user_id, datetime.now(timezone.utc))
        if isinstance(reminder_patch, str):
            return reminder_patch
        update_data.update(reminder_patch)

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

    if "reminderAt" in update_data:
        if update_data["reminderAt"] is None:
            changes.append("reminder cleared")
        else:
            changes.append(f"reminder set for {update_data['reminderAt'].strftime('%Y-%m-%d %H:%M UTC')}")

    return f"Updated drop {drop_id}: {', '.join(changes)}."


# ── Run ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
