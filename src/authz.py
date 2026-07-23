from config import db


def is_trusted_caller(user_id: str) -> bool:
    """True iff the verified caller may create/keep NEVER-EXPIRING (forever) drops.

    Mirrors firestore.rules isTrusted() (firestore.rules:6-16): the OWNER
    (config/owner.data.uid == caller) OR a user whose users/{uid}.tier == 'trusted'.
    DEFAULTS TO STANDARD (False) on a missing users doc, a missing/None/non-'trusted'
    tier field, a missing config/owner doc, OR ANY Firestore read error — matching the
    frontend copy path's fail-closed default (drag-drop-app/src/lib/drops.ts:1649-1651,
    'default to standard on miss/error').

    SECURITY: the firebase_admin Admin SDK (config.py:34) BYPASSES firestore.rules, so
    this helper IS the sole enforcement of the (!isForeverWrite() || isTrusted()) gate
    (firestore.rules:276 create, :291 update) for every agent write. It MUST default to
    standard on any failure so a missing doc or transient error can never grant 'trusted'.
    The owner uid is READ from config/owner (never hardcoded). Never raises.
    """
    # 1. OWNER — config/owner.uid (mirrors isOwner, firestore.rules:6-10).
    try:
        owner_doc = db.collection("config").document("owner").get()
        if owner_doc.exists and (owner_doc.to_dict() or {}).get("uid") == user_id:
            return True
    except Exception:
        pass  # fall through to tier read; fail-closed if that also errors
    # 2. TIER — users/{uid}.tier == 'trusted' (mirrors firestore.rules:13-15).
    #    Doc-miss, missing field, non-'trusted' value, or ANY error -> standard (False).
    try:
        user_doc = db.collection("users").document(user_id).get()
        if user_doc.exists:
            return (user_doc.to_dict() or {}).get("tier") == "trusted"
    except Exception:
        pass
    return False
