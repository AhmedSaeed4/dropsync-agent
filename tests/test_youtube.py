import os
import sys
import time
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
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._api_key_patcher = patch.dict(os.environ, {"YOUTUBE_API_KEY": ""})
        cls._api_key_patcher.start()

    @classmethod
    def tearDownClass(cls):
        cls._api_key_patcher.stop()
        super().tearDownClass()

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


class YouTubeDataApiTests(unittest.TestCase):
    """The official Data API front-runs oEmbed wherever fresh fetches happen."""

    def test_helper_without_key_returns_none_without_http(self):
        with (
            patch.dict(os.environ, {"YOUTUBE_API_KEY": ""}),
            patch.object(youtube, "_http_get_json") as http_mock,
        ):
            self.assertIsNone(youtube.fetch_youtube_titles_data_api(["abc12345678"]))
        http_mock.assert_not_called()

    def test_helper_maps_snippets_trims_and_skips_unusable(self):
        payload = {
            "items": [
                {"id": "abc12345678", "snippet": {"title": "  Padded title  ", "channelTitle": " Chan "}},
                {"id": "def23456789", "snippet": {"title": "   ", "channelTitle": "Ghost"}},
                {"snippet": {"title": "No id here"}},
            ],
        }
        with (
            patch.dict(os.environ, {"YOUTUBE_API_KEY": "k"}),
            patch.object(youtube, "_http_get_json", return_value=(payload, 200, None)) as http_mock,
        ):
            result = youtube.fetch_youtube_titles_data_api(
                ["abc12345678", "def23456789", "zzz98765432"]
            )

        self.assertEqual(result, {"abc12345678": {"title": "Padded title", "channel": "Chan"}})
        requested_url = http_mock.call_args.args[0]
        self.assertTrue(requested_url.startswith("https://www.googleapis.com/youtube/v3/videos?"))
        self.assertIn("id=abc12345678,def23456789,zzz98765432", requested_url)

    def test_helper_returns_none_on_bad_payload_or_status(self):
        for bad in ((None, None, "boom"), ({"items": "nope"}, 200, None), ({"items": []}, 500, None)):
            with (
                patch.dict(os.environ, {"YOUTUBE_API_KEY": "k"}),
                patch.object(youtube, "_http_get_json", return_value=bad),
            ):
                self.assertIsNone(youtube.fetch_youtube_titles_data_api(["abc12345678"]))

    def test_resolve_api_hits_are_cached_and_misses_fall_back_to_oembed(self):
        payload = {"items": [{"id": "abc12345678", "snippet": {"title": "API title", "channelTitle": "Chan A"}}]}
        with (
            patch.dict(os.environ, {"YOUTUBE_API_KEY": "k"}),
            patch.object(youtube, "_read_cached_title", return_value=None),
            patch.object(youtube, "_http_get_json", return_value=(payload, 200, None)),
            patch.object(youtube, "_merge_cached_title") as merge_mock,
            patch.object(
                youtube,
                "fetch_youtube_title",
                return_value=("Oembed title", "Chan B", None, 200),
            ) as fetch_mock,
        ):
            result = youtube.resolve_video_ids(["abc12345678", "def23456789"])

        merge_mock.assert_any_call("abc12345678", "API title", "Chan A")
        self.assertEqual(merge_mock.call_count, 2)
        fetch_mock.assert_called_once_with(
            "def23456789",
            attempt_timeout=youtube.YOUTUBE_RESOLVE_ATTEMPT_TIMEOUT,
            retry_on_timeout=False,
        )
        self.assertEqual(
            result["labels"][0],
            {"videoId": "abc12345678", "title": "API title", "channel": "Chan A", "source": "api"},
        )
        self.assertEqual(result["labels"][1]["title"], "Oembed title")

    def test_resolve_without_key_keeps_the_legacy_oembed_only_path(self):
        with (
            patch.dict(os.environ, {"YOUTUBE_API_KEY": ""}),
            patch.object(youtube, "_read_cached_title", return_value=None),
            patch.object(youtube, "_merge_cached_title"),
            patch.object(
                youtube,
                "fetch_youtube_title",
                return_value=("Oembed title", None, None, 200),
            ) as fetch_mock,
            patch.object(youtube, "_http_get_json") as api_mock,
        ):
            result = youtube.resolve_video_ids(["abc12345678"])

        api_mock.assert_not_called()
        fetch_mock.assert_called_once()
        self.assertEqual(result["labels"][0]["title"], "Oembed title")

    def test_resolve_with_api_failure_falls_back_to_oembed(self):
        with (
            patch.dict(os.environ, {"YOUTUBE_API_KEY": "k"}),
            patch.object(youtube, "_read_cached_title", return_value=None),
            patch.object(youtube, "_merge_cached_title"),
            patch.object(youtube, "_http_get_json", return_value=(None, None, "boom")),
            patch.object(
                youtube,
                "fetch_youtube_title",
                return_value=("Oembed title", None, None, 200),
            ) as fetch_mock,
        ):
            result = youtube.resolve_video_ids(["abc12345678"])

        fetch_mock.assert_called_once()
        self.assertEqual(result["labels"][0]["title"], "Oembed title")


class RecordingCacheDB(SingleCollectionDB):
    """Records youtubeTitles cache writes so tests can prove persistence."""

    def __init__(self):
        super().__init__(FakeDropCollection())
        self.cache_sets: dict[str, dict] = {}

    def collection(self, name):
        if name == tools_server.YOUTUBE_CACHE_COLLECTION:
            parent = self

            class _CacheColl:
                def document(self, doc_id):
                    class _CacheDoc:
                        def set(self, doc_data, **_kwargs):
                            parent.cache_sets[doc_id] = doc_data
                    return _CacheDoc()
            return _CacheColl()
        return super().collection(name)


class AgentMissingTitlesApiTests(unittest.TestCase):
    """get_youtube_titles' fetch stage prefers the batched Data API too."""

    def test_api_hits_answer_cache_writes_and_leftovers_use_oembed(self):
        database = RecordingCacheDB()
        with (
            patch.dict(os.environ, {"YOUTUBE_API_KEY": "k"}),
            patch.object(tools_server, "db", database),
            patch.object(
                tools_server,
                "fetch_youtube_titles_data_api",
                return_value={"abc12345678": {"title": "API title", "channel": "Chan A"}},
            ) as api_mock,
            patch.object(tools_server, "_fetch_youtube_description", return_value="A preview") as desc_mock,
            patch.object(
                tools_server,
                "_fetch_youtube_title",
                return_value=("Oembed title", "Chan B", None),
            ) as fetch_mock,
        ):
            results, fetched, throttled, pending = tools_server._fetch_missing_titles(
                ["abc12345678", "def23456789"], time.monotonic() + 30
            )

        api_mock.assert_called_once_with(["abc12345678", "def23456789"])
        desc_mock.assert_any_call("abc12345678")
        fetch_mock.assert_called_once_with("def23456789")
        self.assertEqual(results["abc12345678"]["status"], "fetched")
        self.assertEqual(results["abc12345678"]["desc"], "A preview")
        self.assertEqual(results["def23456789"]["status"], "fetched")
        self.assertEqual(results["def23456789"]["title"], "Oembed title")
        self.assertEqual(fetched, 1)
        self.assertFalse(throttled)
        self.assertEqual(pending, 0)
        cache_doc = database.cache_sets["abc12345678"]
        self.assertEqual(cache_doc["title"], "API title")
        self.assertEqual(cache_doc["author_name"], "Chan A")
        self.assertEqual(cache_doc["descriptionPreview"], "A preview")

    def test_no_key_leaves_the_whole_loop_as_before(self):
        database = RecordingCacheDB()
        with (
            patch.dict(os.environ, {"YOUTUBE_API_KEY": ""}),
            patch.object(tools_server, "db", database),
            patch.object(tools_server, "fetch_youtube_titles_data_api", return_value=None) as api_mock,
            patch.object(
                tools_server,
                "_fetch_youtube_title",
                return_value=("Oembed title", "Chan B", None),
            ) as fetch_mock,
        ):
            results, fetched, throttled, pending = tools_server._fetch_missing_titles(
                ["abc12345678"], time.monotonic() + 30
            )

        api_mock.assert_called_once_with(["abc12345678"])
        fetch_mock.assert_called_once_with("abc12345678")
        self.assertEqual(fetched, 1)
        self.assertFalse(throttled)
        self.assertEqual(pending, 0)
        self.assertEqual(list(database.cache_sets), ["abc12345678"])


if __name__ == "__main__":
    unittest.main()
