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
from twisted.python import failure
from twisted.web.http import Request
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from matrix_content_scanner.utils.constants import ErrCodes

logger = logging.getLogger(__name__)

JsonDict = Dict[str, Any]


class MatrixRestError(Exception):
    """
    Handled by the jsonwrap wrapper. Any servlets that don't use this
    wrapper should catch this exception themselves.
    """

    def __init__(self, httpStatus: int, errcode: str, error: str) -> None:
        super(Exception, self).__init__(error)
        self.httpStatus = httpStatus
        self.errcode = errcode
        self.error = error


class _AsyncResource(Resource, metaclass=abc.ABCMeta):
    def render(self, request: Request) -> int:
        """This gets called by twisted every time someone sends us a request."""
        defer.ensureDeferred(self._async_render_wrapper(request))
        return NOT_DONE_YET

    async def _async_render_wrapper(self, request: Request) -> None:
        """This is a wrapper that delegates to `_async_render` and handles
        exceptions and return values.
        """
        try:
            callback_return = await self._async_render(request)

            if callback_return is not None:
                code, response = callback_return
                self._send_response(request, code, response)
        except Exception:
            # failure.Failure() fishes the original Failure out
            # of our stack, and thus gives us a sensible stack
            # trace.
            f = failure.Failure()
            self._send_error_response(f, request)

    async def _async_render(self, request: Request) -> Tuple[int, Any]:
        """Delegates to `_async_render_<METHOD>` methods, or returns a 400 if
        no appropriate method exists. Can be overridden in sub classes for
        different routing.
        """
        # Treat HEAD requests as GET requests.
        request_method = request.method.decode("ascii")
        if request_method == "HEAD":
            request_method = "GET"

        method_handler: Callable[[Request], Awaitable[Tuple[int, Any]]] = getattr(self, "on_%s" % (request_method,), None)  # type: ignore[assignment]
        if not method_handler:
            raise MatrixRestError(404, ErrCodes.NOT_FOUND, "Route not found")

        return await method_handler(request)

    @abc.abstractmethod
    def _send_response(
        self,
        request: Request,
        code: int,
        response_object: Any,
    ) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def _send_error_response(
        self,
        f: failure.Failure,
        request: Request,
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
        request.write(dict_to_json_bytes(response_object))
        request.finish()

    def _send_error_response(
        self,
        f: failure.Failure,
        request: Request,
    ) -> None:
        """Implements _AsyncResource._send_error_response"""
        request.setHeader("Content-Type", "application/json")

        if f.check(MatrixRestError) is not None:
            error: MatrixRestError = f.value  # type: ignore[assignment]
            request.setResponseCode(error.httpStatus)
            res = dict_to_json_bytes({"errcode": error.errcode, "error": error.error})
            request.write(res)
        else:
            logger.error("Request processing failed: %r, %s", failure, f.getTraceback())
            request.setResponseCode(500)
            res = dict_to_json_bytes(
                {"errcode": "M_UNKNOWN", "error": "Internal Server Error"}
            )
            request.write(res)

        request.finish()


def dict_to_json_bytes(content: JsonDict) -> bytes:
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

    def _send_error_response(
        self,
        f: failure.Failure,
        request: Request,
    ) -> None:
        """Implements _AsyncResource._send_error_response"""
        request.setHeader("Content-Type", "application/json")

        if f.check(MatrixRestError) is not None:
            error: MatrixRestError = f.value  # type: ignore[assignment]
            request.setResponseCode(error.httpStatus)
            request.write(error.error.encode("utf-8"))
        else:
            logger.exception(f.value)
            request.setResponseCode(500)
            request.write(b"Internal Server Error")

        request.finish()
