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
from typing import Tuple
from unittest.mock import Mock

import aiounittest
from twisted.web.http_headers import Headers

from matrix_content_scanner.utils.errors import ContentScannerRestError
from tests import SMALL_PNG, get_content_scanner


class FileDownloaderTestCase(aiounittest.AsyncTestCase):
    def setUp(self) -> None:
        self.downloader = get_content_scanner().file_downloader

        self.media_status = 200
        self.media_body = SMALL_PNG

        self.media_headers = Headers()
        self.media_headers.setRawHeaders("content-type", ["image/png"])

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
