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
import abc
import json
import logging
from typing import Any, Awaitable, Callable, Dict, Tuple

from twisted.internet import defer
from twisted.web.http import Request
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from matrix_content_scanner.utils.constants import ErrCodes
from matrix_content_scanner.utils.errors import ContentScannerRestError

logger = logging.getLogger(__name__)

JsonDict = Dict[str, Any]


class _AsyncResource(Resource, metaclass=abc.ABCMeta):
    def render(self, request: Request) -> int:
        """This gets called by twisted every time someone sends us a request."""
        defer.ensureDeferred(self._async_render(request))
        return NOT_DONE_YET

    async def _async_render(self, request: Request) -> None:
        """Processes the incoming request asynchronously and handles errors."""
        try:
            # Treat HEAD requests as GET requests.
            request_method = request.method.decode("ascii")
            if request_method == "HEAD":
                request_method = "GET"

            method_handler: Callable[[Request], Awaitable[Tuple[int, Any]]] = getattr(
                self, "on_%s" % (request_method,), None
            )  # type: ignore[assignment]
            if not method_handler:
                raise ContentScannerRestError(
                    404, ErrCodes.NOT_FOUND, "Route not found"
                )

            code, response = await method_handler(request)

            self._send_response(request, code, response)
        except ContentScannerRestError as e:
            request.setResponseCode(e.http_status)
            res = _dict_to_json_bytes({"reason": e.reason, "info": e.info})
            request.write(res)
            request.finish()
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            res = _dict_to_json_bytes(
                {"reason": "M_UNKNOWN", "info": "Internal Server Error"}
            )
            request.write(res)
            request.finish()

    @abc.abstractmethod
    def _send_response(
        self,
        request: Request,
        code: int,
        response_object: Any,
    ) -> None:
        raise NotImplementedError()


class JsonResource(_AsyncResource):
    """A resource that will call `self._async_on_<METHOD>` on new requests,
    formatting responses and errors as JSON.
    """

    def __init__(self) -> None:
        super().__init__()

    def _send_response(
        self,
        request: Request,
        code: int,
        response_object: Any,
    ) -> None:
        """Implements _AsyncResource._send_response"""
        request.setResponseCode(code)
        request.setHeader("Content-Type", "application/json")
        request.write(_dict_to_json_bytes(response_object))
        request.finish()


def _dict_to_json_bytes(content: JsonDict) -> bytes:
    """Converts a dict into JSON and encodes it to bytes."""
    return json.dumps(content).encode("UTF-8")


class BytesResource(_AsyncResource):
    """A resource that will call `self._async_on_<METHOD>` on new requests,
    formatting responses and errors as HTML.
    """

    def _send_response(
        self,
        request: Request,
        code: int,
        response_object: Any,
    ) -> None:
        """Implements _AsyncResource._send_response. Expects the child class to have
        already set the content type header.
        """
        # We expect to get bytes for us to write
        assert isinstance(response_object, bytes)
        request.setResponseCode(code)
        request.write(response_object)
        request.finish()
