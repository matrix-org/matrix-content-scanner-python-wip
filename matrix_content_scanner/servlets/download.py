#  Copyright 2021 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Tuple, Union

from twisted.web.http import Request

from matrix_content_scanner.servlets import (
    BytesResource,
    get_media_metadata_from_request,
)
from matrix_content_scanner.utils.types import JsonDict

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


class DownloadServlet(BytesResource):
    isLeaf = True

    def __init__(self, content_scanner: "MatrixContentScanner"):
        super().__init__()
        self._scanner = content_scanner.scanner

    async def on_GET(self, request: Request) -> Tuple[int, Union[bytes, JsonDict]]:
        # mypy doesn't recognise request.postpath but it does exist and is documented.
        media_path: bytes = b"/".join(request.postpath)  # type: ignore[attr-defined]
        media = await self._scanner.scan_file(media_path.decode("ascii"), None)
        request.setHeader("Content-Type", media.content_type)
        request.setHeader("Content-Length", str(len(media.content)))
        return 200, media.content


class DownloadEncryptedServlet(BytesResource):
    def __init__(self, content_scanner: "MatrixContentScanner"):
        super().__init__()
        self._scanner = content_scanner.scanner
        self._crypto_handler = content_scanner.crypto_handler

    async def on_POST(self, request: Request) -> Tuple[int, Union[bytes, JsonDict]]:
        metadata = get_media_metadata_from_request(request, self._crypto_handler)

        url = metadata["file"]["url"]
        media_path = url[len("mxc://") :]

        media = await self._scanner.scan_file(media_path, metadata)
        request.setHeader("Content-Type", media.content_type)
        request.setHeader("Content-Length", str(len(media.content)))
        return 200, media.content
