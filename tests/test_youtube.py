import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import tools_server
import youtube


# ── Minimal Firestore fakes for the agent save/edit path ──────────────────────

class FakeSnapshot:
    def __init__(self, data):
        self.exists = data is not None
        self._data = data or {}

    def to_dict(self):
        return self._data


class FakeDropDocRef:
    def __init__(self, collection, doc_id):
        self._collection = collection
        self._id = doc_id

    def get(self):
        return FakeSnapshot(self._collection.existing.get(self._id))

    def update(self, update_data):
        self._collection.updates.append(update_data)


class FakeDropCollection:
    """Serves only the 'drops' collection shape used by create_drop/update_drop."""

    def __init__(self, existing=None):
        self.existing = existing or {}
        self.updates: list[dict] = []
        self.added: list[dict] = []

    def document(self, doc_id):
        return FakeDropDocRef(self, doc_id)

    def add(self, doc_data):
        self.added.append(doc_data)
        ref = type("FakeRef", (), {"id": "new-drop"})()
        return (None, ref)


class SingleCollectionDB:
    def __init__(self, collection):
        self._collection = collection

    def collection(self, name):
        return self._collection


def _existing_labeled_drop():
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    return {
        "name": "My links",
        "type": "text",
        "userId": "user-1",
        "workspaceId": None,
        "categories": [],
        "category": None,
        "encrypted": True,
        "content": "old-ciphertext",
        "expiresAt": future,
        "expirationOption": "24h",
        "youtubeVideoLabels": [
            {"videoId": "abc12345678", "title": "Old title", "channel": "Old channel"},
        ],
    }


class YouTubeResolverTests(unittest.TestCase):
    def test_normalize_video_ids_validates_and_deduplicates(self):
        self.assertEqual(
            youtube.normalize_video_ids(["abc12345678", "abc12345678", "bad"]),
            ["abc12345678"],
        )

    @patch.object(youtube, "_read_cached_title")
    @patch.object(youtube, "fetch_youtube_title")
    def test_cache_hit_avoids_oembed(self, fetch_mock, cache_mock):
        cache_mock.return_value = {
            "videoId": "abc12345678",
            "title": "Cached title",
            "channel": "Cached channel",
            "source": "cache",
        }

        result = youtube.resolve_video_ids(["abc12345678"])

        self.assertEqual(result["labels"][0]["title"], "Cached title")
        fetch_mock.assert_not_called()

    @patch.object(youtube, "_merge_cached_title")
    @patch.object(youtube, "_read_cached_title", return_value=None)
    @patch.object(youtube, "fetch_youtube_title", return_value=("Fresh title", "Channel", None, 200))
    def test_successful_fetch_is_cached(self, fetch_mock, cache_mock, merge_mock):
        result = youtube.resolve_video_ids(["abc12345678"])

        self.assertEqual(result["labels"][0]["title"], "Fresh title")
        merge_mock.assert_called_once_with("abc12345678", "Fresh title", "Channel")

    @patch.object(youtube, "_merge_cached_title")
    @patch.object(youtube, "_read_cached_title", return_value=None)
    @patch.object(youtube, "fetch_youtube_title", return_value=(None, None, "unavailable", 404))
    def test_unavailable_video_is_not_cached(self, fetch_mock, cache_mock, merge_mock):
        result = youtube.resolve_video_ids(["abc12345678"])

        self.assertEqual(result["unresolved"][0]["reason"], "unavailable")
        merge_mock.assert_not_called()

    @patch.object(youtube, "_http_get_json")
    def test_fetcher_builds_only_the_fixed_oembed_url(self, http_mock):
        http_mock.return_value = ({"title": "Title", "author_name": "Channel"}, 200, None)

        youtube.fetch_youtube_title("abc12345678")

        requested_url = http_mock.call_args.args[0]
        self.assertTrue(requested_url.startswith("https://www.youtube.com/oembed?"))
        self.assertIn("v%3Dabc12345678", requested_url)

    @patch.object(youtube.requests, "get")
    @patch.object(youtube, "_read_cached_title", return_value=None)
    @patch.object(youtube, "_merge_cached_title")
    def test_resolve_fails_fast_on_hanging_youtube(self, merge_mock, cache_mock, get_mock):
        get_mock.side_effect = youtube.requests.exceptions.ReadTimeout("hang")

        result = youtube.resolve_video_ids(["abc12345678"])

        # ONE short attempt, no retry: the resolve endpoint must answer well
        # inside the frontend's request timeout even when YouTube hangs.
        self.assertEqual(get_mock.call_count, 1)
        self.assertTrue(result["unresolved"][0]["reason"].startswith("network error"))
        merge_mock.assert_not_called()


class AgentSavedLabelTests(unittest.TestCase):
    """Agent-created/edited drops attach saved-video labels from the shared
    youtubeTitles cache. Cache reads ONLY: every test here also proves the
    write path makes zero network calls (no requests.get, no fresh fetcher)."""

    def _cache(self, *pairs):
        return dict(pairs)

    def test_create_drop_attaches_known_labels_in_shape_and_order(self):
        collection = FakeDropCollection()
        cache = {
            "abc12345678": {"videoId": "abc12345678", "title": "First video", "channel": "Chan A"},
            # channel absent from cache -> label must carry channel=None
            "def23456789": {"videoId": "def23456789", "title": "Second video", "channel": None},
        }
        content = (
            "https://www.youtube.com/watch?v=def23456789 first, "
            "then https://youtu.be/abc12345678 and again https://youtu.be/abc12345678"
        )

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "db", SingleCollectionDB(collection)),
            patch.object(tools_server, "encrypt_drop_content", return_value={"content": "ct", "iv": "iv"}),
            patch.object(tools_server, "_read_cached_title", side_effect=lambda vid: cache.get(vid)) as read_mock,
            patch.object(tools_server.requests, "get") as http_mock,
        ):
            result = tools_server.create_drop(name="Links", content=content)

        self.assertIn("Created drop", result)
        self.assertEqual(
            collection.added[0]["youtubeVideoLabels"],
            [
                {"videoId": "def23456789", "title": "Second video", "channel": None},
                {"videoId": "abc12345678", "title": "First video", "channel": "Chan A"},
            ],
        )
        # One cache read per UNIQUE id (3 raw links, 2 unique), appearance order.
        self.assertEqual(read_mock.call_count, 2)
        self.assertEqual(
            [call.args[0] for call in read_mock.call_args_list],
            ["def23456789", "abc12345678"],
        )
        http_mock.assert_not_called()

    def test_create_drop_unknown_video_saves_without_labels_and_zero_network(self):
        collection = FakeDropCollection()

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "db", SingleCollectionDB(collection)),
            patch.object(tools_server, "encrypt_drop_content", return_value={"content": "ct", "iv": "iv"}),
            patch.object(tools_server, "_read_cached_title", return_value=None),
            patch.object(tools_server, "_fetch_youtube_title") as fetch_mock,
            patch.object(tools_server.requests, "get") as http_mock,
        ):
            result = tools_server.create_drop(
                name="Links",
                content="https://youtu.be/zzz98765432",
            )

        self.assertIn("Created drop", result)
        self.assertNotIn("youtubeVideoLabels", collection.added[0])
        fetch_mock.assert_not_called()
        http_mock.assert_not_called()

    def test_update_name_only_keeps_existing_labels(self):
        collection = FakeDropCollection({"drop-1": _existing_labeled_drop()})

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "db", SingleCollectionDB(collection)),
            patch.object(tools_server, "_is_trusted_caller", return_value=True),
            patch.object(tools_server, "_read_cached_title") as read_mock,
            patch.object(tools_server.requests, "get") as http_mock,
        ):
            result = tools_server.update_drop("drop-1", name="Renamed")

        self.assertIn("Updated drop", result)
        update_data = collection.updates[0]
        self.assertEqual(update_data["name"], "Renamed")
        # A rename cannot change which videos a drop links to — the field must
        # not be touched at all (neither replaced nor deleted).
        self.assertNotIn("youtubeVideoLabels", update_data)
        read_mock.assert_not_called()
        http_mock.assert_not_called()

    def test_update_content_with_known_links_replaces_tag_set(self):
        collection = FakeDropCollection({"drop-1": _existing_labeled_drop()})
        cache = {
            "def23456789": {"videoId": "def23456789", "title": "New video", "channel": "New chan"},
        }

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "db", SingleCollectionDB(collection)),
            patch.object(tools_server, "_is_trusted_caller", return_value=True),
            patch.object(tools_server, "encrypt_personal_drop",
                         return_value={"content": "ct", "iv": "iv", "encryptedDEK": "dek", "encrypted": True}),
            patch.object(tools_server, "_read_cached_title", side_effect=lambda vid: cache.get(vid)),
        ):
            result = tools_server.update_drop(
                "drop-1",
                content="now watch https://youtu.be/def23456789 instead",
            )

        self.assertIn("Updated drop", result)
        update_data = collection.updates[0]
        self.assertEqual(update_data["encrypted"], True)
        self.assertEqual(
            update_data["youtubeVideoLabels"],
            [{"videoId": "def23456789", "title": "New video", "channel": "New chan"}],
        )

    def test_update_content_without_links_deletes_labels(self):
        collection = FakeDropCollection({"drop-1": _existing_labeled_drop()})

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "db", SingleCollectionDB(collection)),
            patch.object(tools_server, "_is_trusted_caller", return_value=True),
            patch.object(tools_server, "encrypt_personal_drop",
                         return_value={"content": "ct", "iv": "iv", "encryptedDEK": "dek", "encrypted": True}),
            patch.object(tools_server, "_read_cached_title") as read_mock,
        ):
            result = tools_server.update_drop("drop-1", content="plain words only now")

        self.assertIn("Updated drop", result)
        update_data = collection.updates[0]
        # No links left -> no extraction -> old tags would describe removed
        # videos, so the DELETE_FIELD wipe stays.
        self.assertIs(update_data["youtubeVideoLabels"], tools_server.firestore.DELETE_FIELD)
        read_mock.assert_not_called()

    def test_create_plain_text_drop_has_no_labels_field(self):
        collection = FakeDropCollection()

        with (
            patch.object(tools_server, "_verified_uid", return_value="user-1"),
            patch.object(tools_server, "db", SingleCollectionDB(collection)),
            patch.object(tools_server, "encrypt_drop_content", return_value={"content": "ct", "iv": "iv"}),
            patch.object(tools_server, "_read_cached_title") as read_mock,
            patch.object(tools_server.requests, "get") as http_mock,
        ):
            result = tools_server.create_drop(name="Note", content="no links in here")

        self.assertIn("Created drop", result)
        self.assertNotIn("youtubeVideoLabels", collection.added[0])
        read_mock.assert_not_called()
        http_mock.assert_not_called()


class _KnownLabelsHelperTests(unittest.TestCase):
    """Direct unit tests for the shared helper's contract."""

    def test_partial_knowledge_attaches_known_subset_in_order(self):
        cache = {
            "ghi23456789": {"videoId": "ghi23456789", "title": "Known two", "channel": None},
        }
        text = (
            "https://youtu.be/abc12345678 "
            "https://youtu.be/ghi23456789 "
            "https://youtu.be/xyz98765432"
        )
        with (
            patch.object(tools_server, "_read_cached_title", side_effect=lambda vid: cache.get(vid)) as read_mock,
            patch.object(tools_server.requests, "get") as http_mock,
        ):
            labels = tools_server._known_youtube_labels_for(text)

        self.assertEqual(
            labels,
            [{"videoId": "ghi23456789", "title": "Known two", "channel": None}],
        )
        self.assertEqual(read_mock.call_count, 3)  # one small Firestore get per unique id
        http_mock.assert_not_called()

    def test_no_links_returns_none(self):
        with patch.object(tools_server, "_read_cached_title") as read_mock:
            self.assertIsNone(tools_server._known_youtube_labels_for("just words"))
        read_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
