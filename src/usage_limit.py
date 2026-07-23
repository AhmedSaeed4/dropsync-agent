"""Per-user agent usage limits. Trusted = unlimited (untracked).
Non-trusted = 5 prompts/hour + 25 prompts/day, ROLLING windows: the limit clears
a real 60 min / 24 h after the OLDEST message still inside the window (NOT at a
clock-hour / midnight boundary). Atomic check + prune + append via a Firestore
transaction. No model/LLM calls happen here."""
import asyncio
import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional

from firebase_admin import firestore
from google.api_core import exceptions as gexc
from fastapi import HTTPException

from config import db
from authz import is_trusted_caller

logger = logging.getLogger(__name__)

HOURLY_LIMIT = 5
DAILY_LIMIT = 25
HOUR_WINDOW = timedelta(hours=1)
DAY_WINDOW = timedelta(hours=24)


@dataclass
class UsageDecision:
    allowed: bool
    limit: Optional[str] = None       # "hourly" | "daily" | None
    reset_at: Optional[datetime] = None


def _as_dt(v) -> Optional[datetime]:
    """Normalize a stored value to a tz-aware UTC datetime, or None.
    Firestore returns tz-aware DatetimeWithNanoseconds, but coerce defensively:
    a naive value would TypeError on the arithmetic/comparisons below."""
    if not isinstance(v, datetime):
        return None
    if v.tzinfo is None:
        return v.replace(tzinfo=timezone.utc)
    return v.astimezone(timezone.utc)


def _limit_message(limit: str, reset_at: datetime) -> str:
    assert reset_at.tzinfo == timezone.utc, "reset_at must be tz-aware UTC"
    if limit == "hourly":
        hhmm = reset_at.strftime("%H:%M")
        return f"You've reached the limit of {HOURLY_LIMIT} agent messages per hour. This resets at {hhmm} UTC."
    # daily — rolling window, so the reset is a specific datetime (not midnight)
    dt = reset_at.strftime("%H:%M UTC on %Y-%m-%d")
    return f"You've reached the daily limit of {DAILY_LIMIT} agent messages. This resets at {dt}."


# Per-uid lock: serialize same-user quota checks within this worker so a user
# cannot manufacture optimistic-concurrency exhaustion to farm unlimited access.
_uid_locks: dict[str, asyncio.Lock] = {}


def _get_uid_lock(uid: str) -> asyncio.Lock:
    lock = _uid_locks.get(uid)
    if lock is None:
        lock = asyncio.Lock()
        _uid_locks[uid] = lock
    return lock


# Genuine transient infra errors -> FAIL OPEN (waive the limit for that one request).
# NOTE: Aborted is retried internally by the @firestore.transactional decorator and only
# surfaces as the exhaustion ValueError, which admit_or_raise FAILS CLOSED (503).
_TRANSIENT = (
    gexc.ServiceUnavailable,
    gexc.DeadlineExceeded,
    gexc.InternalServerError,
    ConnectionError,
    TimeoutError,
)


@firestore.transactional
def _check_and_increment(transaction, user_id: str, now: datetime) -> UsageDecision:
    """ROLLING-window quota check. PLAIN def — NOT async (an async def returns a coroutine,
    commits an EMPTY transaction, and silently makes the limit a 100% no-op). `prompts` =
    timestamps of the user's admitted messages still inside the 24 h window (pruned on read).
    Hourly count = entries within HOUR_WINDOW; daily count = all remaining entries.
    `now` is fixed by the caller and reused across SDK retries so the window math is stable."""
    usage_ref = db.collection("usage").document(user_id)
    snap = usage_ref.get(transaction=transaction)
    if snap.exists:
        raw = (snap.to_dict() or {}).get("prompts") or []
        prompts = [t for t in (_as_dt(x) for x in raw) if t is not None]
    else:
        prompts = []
    # Prune entries older than the DAY window (also bounds the array to <= DAILY_LIMIT).
    prompts = [t for t in prompts if (now - t) < DAY_WINDOW]
    hour_entries = [t for t in prompts if (now - t) < HOUR_WINDOW]
    # Check hourly first (resets sooner => most actionable message). Block path writes NOTHING.
    if len(hour_entries) >= HOURLY_LIMIT:
        return UsageDecision(False, "hourly", min(hour_entries) + HOUR_WINDOW)
    if len(prompts) >= DAILY_LIMIT:
        return UsageDecision(False, "daily", min(prompts) + DAY_WINDOW)
    # Admit: append this timestamp + write back atomically (route through the transaction
    # object — firebase-admin's DocumentReference.set() does not accept transaction=).
    prompts.append(now)
    transaction.set(usage_ref, {"prompts": prompts, "updatedAt": now})
    return UsageDecision(True)


async def admit_or_raise(user_id: str) -> None:
    """Call as the FIRST statement in /chat. Raises HTTPException(429) if over limit.
    Trusted users: return immediately (unlimited + untracked; no usage doc created)."""
    if await asyncio.to_thread(is_trusted_caller, user_id):
        return
    now = datetime.now(timezone.utc)  # fixed once; reused across SDK retries
    try:
        async with _get_uid_lock(user_id):
            decision = await asyncio.to_thread(
                _check_and_increment, db.transaction(), user_id, now
            )
    except _TRANSIENT:
        logger.exception("usage txn transient failure; failing OPEN (fairness gate)")
        return
    except Exception:
        logger.exception("usage txn hard failure (logic bug or contention exhaustion); failing CLOSED")
        raise HTTPException(
            status_code=503,
            detail="Couldn't verify your message limit. Please retry in a moment.",
        )
    if not decision.allowed:
        retry_after = max(1, math.ceil((decision.reset_at - now).total_seconds()))
        raise HTTPException(
            status_code=429,
            detail=_limit_message(decision.limit, decision.reset_at),
            headers={"Retry-After": str(retry_after)},
        )
