#  Copyright 2022 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import json
from typing import Tuple, Union
from unittest.mock import Mock

import aiounittest
from twisted.web.http_headers import Headers

from matrix_content_scanner.utils.errors import ContentScannerRestError, \
    WellKnownDiscoveryError
from matrix_content_scanner.utils.types import JsonDict
from tests import SMALL_PNG, get_content_scanner, get_base_media_headers


class FileDownloaderTestCase(aiounittest.AsyncTestCase):
    def setUp(self) -> None:
        self.downloader = get_content_scanner().file_downloader

        self.media_status = 200
        self.media_body = SMALL_PNG

        self.media_headers = get_base_media_headers()

        async def _get(url: str) -> Tuple[int, bytes, Headers]:
            if (
                url.endswith("/_matrix/media/v3/download/foo/bar")
                or "/_matrix/media/v3/thumbnail/foo/bar" in url
                or url.endswith("/_matrix/media/r0/download/foo/bar")
                or "/_matrix/media/r0/thumbnail/foo/bar" in url
            ):
                return self.media_status, self.media_body, self.media_headers
            elif url.endswith("/.well-known/matrix/client"):
                return 404, b"Not found", Headers()

            raise RuntimeError("Unexpected request on %s" % url)

        self.get_mock = Mock(side_effect=_get)
        self.downloader._get = self.get_mock  # type: ignore[assignment]

    async def test_download(self) -> None:
        media = await self.downloader.download_file("foo/bar")
        self.assertEqual(media.content, SMALL_PNG)
        self.assertEqual(media.content_type, "image/png")

        args = self.get_mock.call_args
        self.assertTrue(args[0][0].startswith("https://foo/"))

    async def test_fixed_base_url(self) -> None:
        self.downloader._base_url = "http://my-site.com"
        await self.downloader.download_file("foo/bar")

        args = self.get_mock.call_args
        self.assertTrue(args[0][0].startswith("http://my-site.com/"))
        # Check that we're bypassing well-known discover if a base URL is set
        self.assertEqual(self.get_mock.call_count, 1)

    async def test_retry_on_404(self) -> None:
        self.media_status = 404
        self.media_body = b"Not found"
        self.media_headers.setRawHeaders("content-type", ["text/plain"])

        with self.assertRaises(ContentScannerRestError) as cm:
            await self.downloader.download_file("foo/bar")

        self.assertEqual(cm.exception.http_status, 502)
        self.assertEqual(cm.exception.info, "File not found")

        self.assertEqual(self.get_mock.call_count, 3)

    async def test_thumbnail(self) -> None:
        await self.downloader.download_file("foo/bar", {"height": ["50"]})
        self.assertTrue(
            self.get_mock.call_args[0][0].endswith("/thumbnail/foo/bar?height=50")
        )

    async def test_multiple_content_type(self) -> None:
        self.media_headers.setRawHeaders("content-type", ["image/jpeg", "image/png"])

        with self.assertRaises(ContentScannerRestError) as cm:
            await self.downloader.download_file("foo/bar")

        self.assertEqual(cm.exception.http_status, 502)
        self.assertTrue("Content-Type" in cm.exception.info)

    async def test_no_content_type(self) -> None:
        self.media_headers.removeHeader("content-type")

        with self.assertRaises(ContentScannerRestError) as cm:
            await self.downloader.download_file("foo/bar")

        self.assertEqual(cm.exception.http_status, 502)
        self.assertTrue("Content-Type" in cm.exception.info)


class WellKnownDiscoveryTestCase(aiounittest.AsyncTestCase):
    def setUp(self) -> None:
        self.downloader = get_content_scanner().file_downloader

        self.well_known_status = 200
        self.well_known_body: Union[bytes, JsonDict] = b''

        self.versions_status = 200

        async def _get(url: str) -> Tuple[int, bytes, Headers]:
            if url.endswith("/.well-known/matrix/client"):
                if isinstance(self.well_known_body, bytes):
                    body_bytes = self.well_known_body
                else:
                    body_bytes = json.dumps(self.well_known_body).encode("utf-8")

                return self.well_known_status, body_bytes, Headers()
            elif url.endswith("/_matrix/client/versions"):
                return self.versions_status, b'{}', Headers()
            elif url.endswith("/_matrix/media/v3/download/foo/bar"):
                return 200, SMALL_PNG, get_base_media_headers()

            raise RuntimeError("Unexpected request on %s" % url)

        self.get_mock = Mock(side_effect=_get)
        self.downloader._get = self.get_mock  # type: ignore[assignment]

    async def test_discover(self) -> None:
        self.well_known_body = {"m.homeserver": {"base_url": "https://foo.bar"}}

        await self.downloader.download_file("foo/bar")

        self.assertEqual(self.get_mock.call_count, 3, self.get_mock.mock_calls)

        calls = self.get_mock.mock_calls

        self.assertEqual(calls[0].args[0], "https://foo/.well-known/matrix/client")
        self.assertTrue(calls[1].args[0], "https://foo.bar/_matrix/client/versions")

    async def test_error_status(self) -> None:
        self.well_known_status = 401
        await self._assert_discovery_fail()

    async def test_malformed_content(self) -> None:
        self.well_known_body = {"m.homeserver": "https://foo.bar"}
        await self._assert_discovery_fail()

    async def test_not_valid_homeserver(self) -> None:
        self.versions_status = 404
        await self._assert_discovery_fail()

    async def test_404_no_fail(self) -> None:
        self.well_known_status = 404
        res = await self.downloader._discover_via_well_known("foo")
        self.assertIsNone(res)

    async def _assert_discovery_fail(self) -> None:
        with self.assertRaises(WellKnownDiscoveryError):
            await self.downloader._discover_via_well_known("foo")
