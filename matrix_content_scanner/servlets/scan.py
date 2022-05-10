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
import json
from typing import TYPE_CHECKING, Tuple

from twisted.web.http import Request

from matrix_content_scanner.servlets import JsonDict, JsonResource
from matrix_content_scanner.utils.constants import ErrCodes
from matrix_content_scanner.utils.encrypted_file_metadata import (
    validate_encrypted_file_metadata,
)
from matrix_content_scanner.utils.errors import FileDirtyError, ContentScannerRestError

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


class ScanServlet(JsonResource):
    isLeaf = True

    def __init__(self, content_scanner: "MatrixContentScanner") -> None:
        super().__init__()
        self._scanner = content_scanner.scanner

    async def on_GET(self, request: Request) -> Tuple[int, JsonDict]:
        # mypy doesn't recognise request.postpath but it does exist and is documented.
        media_path: bytes = b"/".join(request.postpath)  # type: ignore[attr-defined]

        try:
            await self._scanner.scan_file(media_path.decode("ascii"), None)
        except FileDirtyError:
            clean = False
        else:
            clean = True

        return 200, {"clean": clean}


class ScanEncryptedServlet(JsonResource):
    def __init__(self, content_scanner: "MatrixContentScanner") -> None:
        super().__init__()
        self._scanner = content_scanner.scanner

    async def on_POST(self, request: Request) -> Tuple[int, JsonDict]:
        assert request.content is not None
        body = request.content.read().decode("ascii")

        try:
            metadata = json.loads(body)
        except json.decoder.JSONDecodeError as e:
            raise ContentScannerRestError(400, ErrCodes.MALFORMED_JSON, str(e))

        validate_encrypted_file_metadata(metadata)

        url = metadata["file"]["url"]
        media_path = url[len("mxc://") :]

        try:
            await self._scanner.scan_file(media_path.decode("ascii"), metadata)
        except FileDirtyError:
            clean = False
        else:
            clean = True

        return 200, {"clean": clean}
