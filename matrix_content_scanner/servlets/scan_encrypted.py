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
from typing import TYPE_CHECKING

from matrix_common.servlet import json_servlet_async
from twisted.web.http import Request
from twisted.web.resource import Resource

from matrix_content_scanner.utils.encrypted_file_metadata import (
    validate_encrypted_file_metadata,
)

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


class ScanEncryptedServlet(Resource):
    def __init__(self, content_scanner: "MatrixContentScanner"):
        super().__init__()
        self._scanner = content_scanner.scanner

    @json_servlet_async
    async def render_POST(self, request: Request):
        body = request.content.read().decode("ascii")
        metadata = json.loads(body)

        validate_encrypted_file_metadata(metadata)

        url = metadata["file"]["url"]
        media_path = url[len("mxc://"):]

        result = await self._scanner.scan_file(media_path, metadata)
        return {"clean": result}
