"""Order 38 - update_drop file-drop coverage.

The tool must accept METADATA updates (name / expiration) on file drops, keep
every existing gate (ownership, password, forever/trusted-tier, call drops), and
reject content + reminder edits on file drops with ZERO Firestore writes.
Text-drop behavior is unchanged (regression test included). All Firestore access
is mocked - these tests never touch real data.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import tools_server


class FakeDoc:
    def __init__(self, data):
        self.exists = True
        self._data = data

    def to_dict(self):
        return self._data


class FakeDocRef:
    """drops/{id} handle: get() serves the fixture, update() records every patch."""

    def __init__(self, data):
        self.doc = FakeDoc(data)
        self.updates = []

    def get(self):
        return self.doc

    def update(self, written):
        self.updates.append(written)


class FakeDropsDB:
    """Only the drops collection may be touched by these metadata-only flows."""

    def __init__(self, refs):
        self.refs = refs

    def collection(self, name):
        assert name == "drops", f"unexpected collection touched: {name}"
        return self

    def document(self, drop_id):
        return self.refs[drop_id]


def make_drop(drop_id="d1", **over):
    base = {
        "name": "photo.png",
        "type": "file",
        "userId": "user-1",
        "workspaceId": None,
        "categories": [],
        "fileSize": 2048,
        "expirationOption": "2h",
        "expiresAt": datetime.now(timezone.utc) + timedelta(hours=2),
    }
    base.update(over)
    ref = FakeDocRef(base)
    return ref, FakeDropsDB({drop_id: ref})


class UpdateDropFileTests(unittest.TestCase):
    def run_tool(self, db, trusted=True, **kwargs):
        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "db", db),
            patch.object(tools_server, "_is_trusted_caller", return_value=trusted),
        ):
            return tools_server.update_drop(**kwargs)

    def test_file_drop_rename_updates_only_name(self):
        ref, db = make_drop()
        result = self.run_tool(db, drop_id="d1", name="Sunset photo")
        self.assertEqual(ref.updates, [{"name": "Sunset photo"}])
        self.assertIn("Updated drop d1: name -> 'Sunset photo'", result)

    def test_file_drop_content_edit_rejected_zero_writes(self):
        ref, db = make_drop()
        result = self.run_tool(db, drop_id="d1", content="new bytes")
        self.assertIn("edited through the assistant", result)
        self.assertEqual(ref.updates, [])

    def test_file_drop_reminder_rejected_zero_writes(self):
        ref, db = make_drop()
        result = self.run_tool(db, drop_id="d1", reminder="15m")
        self.assertIn("carry a reminder", result)
        self.assertEqual(ref.updates, [])

    def test_call_drop_still_rejected(self):
        ref, db = make_drop(type="call")
        result = self.run_tool(db, drop_id="d1", name="nope")
        self.assertIn("Only text and file drops can be updated", result)
        self.assertEqual(ref.updates, [])

    def test_text_drop_rename_still_works(self):
        ref, db = make_drop(type="text")
        result = self.run_tool(db, drop_id="d1", name="New title")
        self.assertEqual(ref.updates, [{"name": "New title"}])
        self.assertIn("Updated drop d1", result)

    def test_file_drop_expiration_change_writes_option_and_expiry(self):
        before = datetime.now(timezone.utc)
        ref, db = make_drop()
        result = self.run_tool(db, drop_id="d1", expiration="6h")
        self.assertEqual(len(ref.updates), 1)
        written = ref.updates[0]
        self.assertEqual(written["expirationOption"], "6h")
        self.assertGreaterEqual(
            written["expiresAt"], before + timedelta(hours=6) - timedelta(seconds=5)
        )
        self.assertIn("expiration -> 6h", result)

    def test_file_drop_forever_requires_trusted(self):
        ref, db = make_drop()
        result = self.run_tool(db, trusted=False, drop_id="d1", expiration="forever")
        self.assertIn("isn't trusted", result)
        self.assertEqual(ref.updates, [])

    def test_edit_existing_forever_file_drop_requires_trusted(self):
        ref, db = make_drop(expirationOption="forever", expiresAt=None)
        result = self.run_tool(db, trusted=False, drop_id="d1", name="rename")
        self.assertIn("never expires", result)
        self.assertEqual(ref.updates, [])

    def test_trusted_user_can_edit_existing_forever_file_drop(self):
        ref, db = make_drop(expirationOption="forever", expiresAt=None)
        result = self.run_tool(db, trusted=True, drop_id="d1", name="rename")
        self.assertEqual(ref.updates, [{"name": "rename"}])
        self.assertIn("Updated drop d1", result)

    def test_personal_file_drop_of_another_user_denied(self):
        ref, db = make_drop(userId="user-2")
        result = self.run_tool(db, drop_id="d1", name="steal")
        self.assertIn("Access denied", result)
        self.assertEqual(ref.updates, [])


if __name__ == "__main__":
    unittest.main()
