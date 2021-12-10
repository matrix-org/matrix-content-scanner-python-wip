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
from typing import TYPE_CHECKING

from matrix_common.servlet import json_servlet_async
from twisted.web.http import Request
from twisted.web.resource import Resource

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


class ScanServlet(Resource):
    isLeaf = True

    def __init__(self, content_scanner: "MatrixContentScanner"):
        super().__init__()
        self._scanner = content_scanner.scanner

    @json_servlet_async
    async def render_GET(self, request: Request):
        media_path: bytes = b"/".join(request.postpath)
        result = await self._scanner.scan_file(media_path.decode("ascii"), {})
        return {"clean": result}
