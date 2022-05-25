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
import copy
from typing import Dict, List, Optional
from unittest.mock import Mock

import aiounittest
from twisted.web.http_headers import Headers

from matrix_content_scanner.utils.constants import ErrCodes
from matrix_content_scanner.utils.errors import ContentScannerRestError, FileDirtyError
from matrix_content_scanner.utils.types import MediaDescription
from tests.testutils import (
    ENCRYPTED_FILE_METADATA,
    SMALL_PNG,
    SMALL_PNG_ENCRYPTED,
    get_content_scanner,
)


class ScannerTestCase(aiounittest.AsyncTestCase):
    def setUp(self) -> None:
        self.downloader_res = MediaDescription(
            content_type="image/png",
            content=SMALL_PNG,
            response_headers=Headers(),
        )

        async def download_file(
            media_path: str,
            thumbnail_params: Optional[Dict[str, List[str]]] = None,
        ) -> MediaDescription:
            return self.downloader_res

        self.downloader_mock = Mock(side_effect=download_file)

        mcs = get_content_scanner()
        mcs.file_downloader.download_file = self.downloader_mock  # type: ignore[assignment]
        self.scanner = mcs.scanner

    async def test_scan(self) -> None:
        media = await self.scanner.scan_file("foo/bar")
        self.assertEqual(media.content, SMALL_PNG)

    async def test_scan_dirty(self) -> None:
        self.scanner._script = "false"
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file("foo/bar")

    async def test_encrypted_file(self) -> None:
        self._setup_encrypted()

        media = await self.scanner.scan_file("foo/bar", ENCRYPTED_FILE_METADATA)
        self.assertEqual(media.content, SMALL_PNG_ENCRYPTED)

    async def test_cache(self) -> None:
        await self.scanner.scan_file("foo/bar")
        self.assertEqual(self.downloader_mock.call_count, 1)

        media = await self.scanner.scan_file("foo/bar")
        self.assertEqual(self.downloader_mock.call_count, 1)
        self.assertEqual(media.content, SMALL_PNG)

    async def test_cache_encrypted(self) -> None:
        self._setup_encrypted()

        await self.scanner.scan_file("foo/bar", ENCRYPTED_FILE_METADATA)
        self.assertEqual(self.downloader_mock.call_count, 1)

        media = await self.scanner.scan_file("foo/bar", ENCRYPTED_FILE_METADATA)
        self.assertEqual(self.downloader_mock.call_count, 1)
        self.assertEqual(media.content, SMALL_PNG_ENCRYPTED)

    async def test_cache_download_thumbnail(self) -> None:
        await self.scanner.scan_file("foo/bar")
        self.assertEqual(self.downloader_mock.call_count, 1)

        await self.scanner.scan_file("foo/bar", thumbnail_params={"width": ["50"]})
        self.assertEqual(self.downloader_mock.call_count, 2)

    async def test_different_encryption_key(self) -> None:
        """Tests that if some of the file's metadata changed, we don't match against the
        cache and we download the file again.

        Also tests that the scanner fails in the correct way if it can't decrypt a file.
        """
        self._setup_encrypted()

        await self.scanner.scan_file("foo/bar", ENCRYPTED_FILE_METADATA)
        self.assertEqual(self.downloader_mock.call_count, 1)

        modified_metadata = copy.deepcopy(ENCRYPTED_FILE_METADATA)
        modified_metadata["file"]["key"]["k"] = "somethingelse"

        with self.assertRaises(ContentScannerRestError) as cm:
            await self.scanner.scan_file("foo/bar", modified_metadata)

        self.assertEqual(cm.exception.http_status, 400)
        self.assertEqual(cm.exception.reason, ErrCodes.FAILED_TO_DECRYPT)

        self.assertEqual(self.downloader_mock.call_count, 2)

    async def test_mimetype(self) -> None:
        self.scanner._allowed_mimetypes = ["image/jpeg"]

        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file("foo/bar")

    async def test_mimetype_encrypted(self) -> None:
        self._setup_encrypted()

        self.scanner._allowed_mimetypes = ["image/jpeg"]

        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file("foo/bar", ENCRYPTED_FILE_METADATA)

    async def test_dont_cache_exit_codes(self) -> None:
        self.scanner._exit_codes_to_ignore = [5]

        # It's tricky to give a value to `scanner._script` that makes `_run_scan` return 5
        # directly, so we just mock it here.
        run_scan_mock = Mock(return_value=5)
        self.scanner._run_scan = run_scan_mock  # type: ignore[assignment]

        # Scan the file, we'll check later that it wasn't cached.
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file("foo/bar")

        self.assertEqual(self.downloader_mock.call_count, 1)

        # Update the mock so that the file is cached at the next scan.
        run_scan_mock.return_value = 1

        # Scan the file again to check that the file wasn't cached.
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file("foo/bar")

        self.assertEqual(self.downloader_mock.call_count, 2)

        # The file should be cached now.
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file("foo/bar")

        self.assertEqual(self.downloader_mock.call_count, 2)

    async def test_outside_temp_dir(self) -> None:
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file("../bar")

    def _setup_encrypted(self) -> None:
        self.downloader_res.content_type = "application/octet-stream"
        self.downloader_res.content = SMALL_PNG_ENCRYPTED
