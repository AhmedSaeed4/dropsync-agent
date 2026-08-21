import contextlib
import io
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import decrypt
import tools_server


class FakeDoc:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = data
        self.exists = True

    def to_dict(self):
        return self._data


class RecordingQuery:
    def __init__(self, docs):
        self.docs = docs
        self.order_by_args = None
        self.limit_value = None
        self.timeout = None

    def where(self, *args):
        return self

    def order_by(self, *args, **kwargs):
        self.order_by_args = (args, kwargs)
        return self

    def limit(self, value):
        self.limit_value = value
        return self

    def stream(self, timeout=None):
        self.timeout = timeout
        return iter(self.docs)


class FakeDB:
    def __init__(self, query):
        self.query = query

    def collection(self, name):
        return self.query


class ListDropsTests(unittest.TestCase):
    def test_list_caches_decryption_and_workspace_names_and_skips_expired(self):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        expired = datetime.now(timezone.utc) - timedelta(minutes=1)
        docs = [
            FakeDoc(
                "current",
                {
                    "name": "Current drop",
                    "type": "text",
                    "content": "encrypted-current",
                    "encrypted": True,
                    "expiresAt": future,
                },
            ),
            FakeDoc(
                "current-2",
                {
                    "name": "Current drop two",
                    "type": "text",
                    "content": "encrypted-current-2",
                    "encrypted": True,
                    "expiresAt": future,
                },
            ),
            FakeDoc(
                "expired",
                {
                    "name": "Expired drop",
                    "type": "text",
                    "content": "encrypted-expired",
                    "encrypted": True,
                    "expiresAt": expired,
                },
            ),
        ]
        query = RecordingQuery(docs)

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "db", FakeDB(query)),
            patch.object(tools_server, "decrypt_drop_content", return_value="preview") as decrypt_mock,
            patch.object(tools_server, "_format_drop", return_value="formatted") as format_mock,
        ):
            result = tools_server.list_drops()

        # The count header (PR #27) must lead the list: models miscount long
        # lists, so the computed total is printed up top. 2 live drops, both
        # text; the expired one is excluded before counting.
        self.assertEqual(
            result,
            "2 personal drops (2 text, 0 file; password and expired drops not included):\nformatted\nformatted",
        )
        self.assertEqual(decrypt_mock.call_count, 2)
        first_cache = decrypt_mock.call_args_list[0].kwargs["cache"]
        second_cache = decrypt_mock.call_args_list[1].kwargs["cache"]
        self.assertIs(first_cache, second_cache)
        self.assertIsInstance(first_cache, decrypt.DecryptionCache)
        self.assertEqual(first_cache.firestore_timeout, tools_server.SEARCH_FIRESTORE_TIMEOUT_SECONDS)
        self.assertEqual(format_mock.call_count, 2)
        first_names = format_mock.call_args_list[0].args[3]
        second_names = format_mock.call_args_list[1].args[3]
        self.assertIs(first_names, second_names)
        self.assertEqual(first_names, {})
        self.assertEqual(format_mock.call_args_list[0].kwargs["timeout"], tools_server.SEARCH_FIRESTORE_TIMEOUT_SECONDS)


class SearchDropsTests(unittest.TestCase):
    def test_search_normalizes_categories_and_excludes_expired_password_drops(self):
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        expired = datetime.now(timezone.utc) - timedelta(minutes=1)
        docs = [
            FakeDoc(
                "array-drop",
                {
                    "name": "Important array drop",
                    "categories": ["Important", "Work"],
                    "category": None,
                    "type": "file",
                    "expiresAt": future,
                },
            ),
            FakeDoc(
                "legacy-drop",
                {
                    "name": "Legacy drop",
                    "categories": [],
                    "category": "Legacy",
                    "type": "file",
                    "expiresAt": future,
                },
            ),
            FakeDoc(
                "expired-drop",
                {
                    "name": "Expired important drop",
                    "categories": ["Important"],
                    "type": "file",
                    "expiresAt": expired,
                },
            ),
            FakeDoc(
                "password-drop",
                {
                    "name": "Important password drop",
                    "categories": ["password"],
                    "type": "text",
                    "content": "encrypted",
                    "encrypted": True,
                    "expiresAt": future,
                },
            ),
        ]

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "_get_all_accessible_drops", return_value=(docs, False)),
            patch.object(tools_server, "decrypt_drop_content", return_value="should not be needed") as decrypt_mock,
        ):
            result = tools_server.search_drops("important")

        self.assertIn("Important array drop", result)
        self.assertIn("category=Important, Work", result)
        self.assertNotIn("Expired important drop", result)
        self.assertNotIn("Important password drop", result)
        decrypt_mock.assert_not_called()

    def test_search_can_match_legacy_category(self):
        doc = FakeDoc(
            "legacy-drop",
            {
                "name": "A drop",
                "category": "Legacy",
                "type": "file",
            },
        )

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "_get_all_accessible_drops", return_value=([doc], False)),
        ):
            result = tools_server.search_drops("legacy")

        self.assertIn("A drop", result)
        self.assertIn("category=Legacy", result)

    def test_search_reads_all_documents_without_cap_or_ordering(self):
        docs = [FakeDoc(str(i), {"name": str(i)}) for i in range(3)]
        query = RecordingQuery(docs)
        deadline = time.monotonic() + 5

        with patch.object(tools_server, "db", FakeDB(query)), patch.object(
            tools_server, "_get_user_workspace_ids", return_value=([], False)
        ):
            selected, incomplete = tools_server._get_all_accessible_drops(
                "user-1",
                deadline,
            )

        self.assertEqual([doc.id for doc in selected], ["0", "1", "2"])
        self.assertFalse(incomplete)
        self.assertIsNone(query.order_by_args)
        self.assertIsNone(query.limit_value)
        self.assertLessEqual(query.timeout, tools_server.SEARCH_FIRESTORE_TIMEOUT_SECONDS)

    def test_search_stream_stops_when_deadline_is_exhausted(self):
        query = RecordingQuery([FakeDoc("late", {"name": "late"})])

        selected, incomplete = tools_server._stream_search_docs(
            query,
            time.monotonic() - 1,
            "expired deadline",
        )

        self.assertEqual(selected, [])
        self.assertTrue(incomplete)
        self.assertIsNone(query.timeout)

    def test_search_reports_incomplete_when_time_budget_is_exhausted(self):
        doc = FakeDoc("match", {"name": "important result", "type": "file"})

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "_get_all_accessible_drops", return_value=([doc], True)),
        ):
            result = tools_server.search_drops("important")

        self.assertIn("Search incomplete", result)
        self.assertIn("important result", result)


class DecryptionCacheTests(unittest.TestCase):
    def test_personal_key_is_loaded_once_per_cache(self):
        cache = decrypt.DecryptionCache(firestore_timeout=5)
        drop = {"encrypted": True, "content": "ciphertext"}

        with (
            patch.object(decrypt, "_get_shared_secret", return_value=b"secret") as get_key,
            patch.object(decrypt, "decrypt_personal_drop", return_value="content"),
        ):
            decrypt.decrypt_drop_content("user-1", drop, cache=cache)
            decrypt.decrypt_drop_content("user-1", drop, cache=cache)

        self.assertEqual(get_key.call_count, 1)
        get_key.assert_called_once_with("user-1", timeout=5)

    def test_workspace_key_is_loaded_once_per_cache(self):
        cache = decrypt.DecryptionCache(firestore_timeout=5)
        drop = {"encrypted": True, "workspaceId": "workspace-1", "content": "ciphertext"}

        with (
            patch.object(decrypt, "_get_workspace_key_data", return_value=b"key") as get_key,
            patch.object(decrypt, "decrypt_workspace_drop", return_value="content"),
        ):
            decrypt.decrypt_drop_content("user-1", drop, cache=cache)
            decrypt.decrypt_drop_content("user-1", drop, cache=cache)

        self.assertEqual(get_key.call_count, 1)
        get_key.assert_called_once_with("workspace-1", timeout=5)

    def test_decryption_errors_do_not_write_to_stdout(self):
        stdout = io.StringIO()
        with patch.object(decrypt, "_get_shared_secret", side_effect=ValueError("bad key")):
            with contextlib.redirect_stdout(stdout):
                result = decrypt.decrypt_personal_drop("user-1", {})

        self.assertIsNone(result)
        self.assertEqual(stdout.getvalue(), "")


class YouTubeLabelSearchTests(unittest.TestCase):
    def test_search_matches_saved_title_and_channel_without_decrypting_password_drop(self):
        docs = [
            FakeDoc(
                "video-drop",
                {
                    "name": "Saved links",
                    "type": "text",
                    "youtubeVideoLabels": [
                        {"videoId": "abc12345678", "title": "Loneliness in winter", "channel": "Quiet Channel"}
                    ],
                    "expiresAt": datetime.now(timezone.utc) + timedelta(hours=1),
                },
            ),
            FakeDoc(
                "password-video-drop",
                {
                    "name": "Private links",
                    "type": "text",
                    "categories": ["password"],
                    "youtubeVideoLabels": [
                        {"videoId": "xyz98765432", "title": "Loneliness private", "channel": "Private"}
                    ],
                    "expiresAt": datetime.now(timezone.utc) + timedelta(hours=1),
                },
            ),
        ]

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "_get_all_accessible_drops", return_value=(docs, False)),
            patch.object(tools_server, "decrypt_drop_content", return_value="should not be needed") as decrypt_mock,
        ):
            result = tools_server.search_drops("loneliness")

        self.assertIn("Loneliness in winter", result)
        self.assertIn("Quiet Channel", result)
        self.assertNotIn("Loneliness private", result)
        decrypt_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
