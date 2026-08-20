"""Shared, bounded YouTube title resolution for DropSync.

This module accepts video IDs rather than arbitrary URLs.  It uses the existing
backend-only ``youtubeTitles`` drawer as a success-only cache and fetches only
YouTube's keyless oEmbed endpoint through ``requests``.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import requests
from firebase_admin import firestore

from config import db

logger = logging.getLogger(__name__)

YOUTUBE_CACHE_COLLECTION = "youtubeTitles"
YOUTUBE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
YOUTUBE_REQUEST_TIMEOUT = 8.0
YOUTUBE_FETCH_DELAY = 0.4
YOUTUBE_RESOLVE_MAX_IDS = 10
YOUTUBE_RESOLVE_FRESH_CAP = 5
YOUTUBE_RESOLVE_TIME_BUDGET = 12.0


def normalize_video_ids(video_ids: list[Any]) -> list[str]:
    """Validate, deduplicate, and preserve the caller's ID order."""
    result: list[str] = []
    seen: set[str] = set()
    for value in video_ids:
        if not isinstance(value, str):
            continue
        video_id = value.strip()
        if not YOUTUBE_ID_RE.fullmatch(video_id) or video_id in seen:
            continue
        seen.add(video_id)
        result.append(video_id)
    return result


def _http_get_json(url: str) -> tuple[dict | None, int | None, str | None]:
    """Fetch JSON with requests; never use stdlib HTTPS in the HF container."""
    headers = {"User-Agent": "Mozilla/5.0 (compatible; DropSync-Assistant/1.0)"}
    last_error = "network error reaching YouTube"
    for attempt in (1, 2):
        try:
            response = requests.get(
                url,
                timeout=YOUTUBE_REQUEST_TIMEOUT,
                headers=headers,
            )
            try:
                return response.json(), response.status_code, None
            except ValueError:
                return None, response.status_code, "unexpected response from YouTube"
        except requests.exceptions.RequestException as exc:
            last_error = f"network error reaching YouTube ({type(exc).__name__})"
            logger.warning(
                "YouTube request failed (attempt %d): %s",
                attempt,
                type(exc).__name__,
            )
            if attempt == 1:
                time.sleep(1.0)
    return None, None, last_error


def fetch_youtube_title(video_id: str) -> tuple[str | None, str | None, str | None, int | None]:
    """Fetch title/channel for one already-validated ID from the fixed oEmbed URL."""
    if not YOUTUBE_ID_RE.fullmatch(video_id):
        return None, None, "invalid video id", None

    # The URL is constructed from a validated ID.  The endpoint never accepts a
    # caller-supplied URL, so this cannot become an arbitrary proxy.
    oembed_url = (
        "https://www.youtube.com/oembed?"
        f"url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3D{video_id}&format=json"
    )
    data, status, error = _http_get_json(oembed_url)
    if status in (400, 401, 403, 404):
        return None, None, "unavailable", status
    if status == 429:
        return None, None, "throttled", status
    if data is None:
        return None, None, error or "temporary", status

    title = data.get("title")
    if not isinstance(title, str) or not title.strip():
        return None, None, "temporary", status

    channel = data.get("author_name")
    if not isinstance(channel, str) or not channel.strip():
        channel = None
    else:
        channel = channel.strip()[:200]

    return title.strip()[:500], channel, None, status


def _read_cached_title(video_id: str) -> dict[str, Any] | None:
    try:
        snapshot = db.collection(YOUTUBE_CACHE_COLLECTION).document(video_id).get(timeout=5.0)
    except Exception as exc:
        logger.warning("YouTube title cache read failed: %s", type(exc).__name__)
        return None

    data = snapshot.to_dict() if snapshot.exists else None
    if not isinstance(data, dict):
        return None
    title = data.get("title")
    if not isinstance(title, str) or not title.strip():
        # Old/unavailable markers are not successful title cache entries.
        return None

    channel = data.get("author_name")
    if not isinstance(channel, str) or not channel.strip():
        channel = None
    else:
        channel = channel.strip()[:200]

    return {
        "videoId": video_id,
        "title": title.strip()[:500],
        "channel": channel,
        "source": "cache",
    }


def _merge_cached_title(video_id: str, title: str, channel: str | None) -> None:
    """Write only a successful title and preserve unrelated drawer fields."""
    try:
        db.collection(YOUTUBE_CACHE_COLLECTION).document(video_id).set(
            {
                "videoId": video_id,
                "title": title,
                "author_name": channel,
                "fetchedAt": firestore.SERVER_TIMESTAMP,
            },
            merge=True,
        )
    except Exception as exc:
        # The caller can still label the drop.  Cache persistence is best effort.
        logger.warning("YouTube title cache write failed: %s", type(exc).__name__)


def resolve_video_ids(
    video_ids: list[Any],
    *,
    max_ids: int = YOUTUBE_RESOLVE_MAX_IDS,
    fresh_cap: int = YOUTUBE_RESOLVE_FRESH_CAP,
    time_budget: float = YOUTUBE_RESOLVE_TIME_BUDGET,
) -> dict[str, Any]:
    """Resolve IDs from cache first, then fetch a small paced number of misses.

    The return value is JSON-ready and deliberately contains no drop data.  A
    caller should not immediately retry ``pending`` or ``throttled`` entries;
    the frontend defers them to a later explicit action.
    """
    ordered = normalize_video_ids(video_ids)[:max_ids]
    labels: list[dict[str, Any]] = []
    unresolved: list[dict[str, str]] = []
    misses: list[str] = []

    for video_id in ordered:
        cached = _read_cached_title(video_id)
        if cached:
            labels.append(cached)
        else:
            misses.append(video_id)

    deadline = time.monotonic() + max(1.0, time_budget)
    fetched = 0
    throttled = False

    for index, video_id in enumerate(misses):
        if throttled or fetched >= fresh_cap or time.monotonic() >= deadline:
            unresolved.extend(
                {"videoId": pending_id, "reason": "pending"}
                for pending_id in misses[index:]
            )
            break

        if fetched > 0:
            time.sleep(YOUTUBE_FETCH_DELAY)

        title, channel, error, _status = fetch_youtube_title(video_id)
        fetched += 1
        if title is None:
            reason = error or "temporary"
            if reason == "throttled":
                throttled = True
            unresolved.append({"videoId": video_id, "reason": reason})
            continue

        _merge_cached_title(video_id, title, channel)
        labels.append(
            {
                "videoId": video_id,
                "title": title,
                "channel": channel,
                "source": "oembed",
            }
        )

    labels.sort(key=lambda item: ordered.index(item["videoId"]))
    resolved_ids = {item["videoId"] for item in labels}
    unresolved_ids = {item["videoId"] for item in unresolved}
    for video_id in ordered:
        if video_id not in resolved_ids and video_id not in unresolved_ids:
            unresolved.append({"videoId": video_id, "reason": "temporary"})

    return {
        "labels": labels,
        "unresolved": unresolved,
        "throttled": throttled,
        "retryAfterSeconds": 60 if throttled else None,
    }
