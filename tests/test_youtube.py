import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import youtube


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


if __name__ == "__main__":
    unittest.main()
