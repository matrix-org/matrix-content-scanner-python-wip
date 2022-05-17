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
from typing import Any, Awaitable, Callable, Optional, Tuple

from twisted.internet import defer
from twisted.web.http import Request
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from matrix_content_scanner import logging
from matrix_content_scanner.crypto import CryptoHandler
from matrix_content_scanner.logging import (
    set_context_from_request,
    set_media_path_in_context,
)
from matrix_content_scanner.utils.constants import ErrCodes
from matrix_content_scanner.utils.encrypted_file_metadata import (
    validate_encrypted_file_metadata,
)
from matrix_content_scanner.utils.errors import ContentScannerRestError
from matrix_content_scanner.utils.types import JsonDict

logger = logging.getLogger(__name__)


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

            set_context_from_request(request)

            code, response = await method_handler(request)

            self._send_response(request, code, response)
        except ContentScannerRestError as e:
            self._send_error(
                request, e.http_status, {"reason": e.reason, "info": e.info}
            )
        except Exception as e:
            logger.exception(e)
            self._send_error(
                request, 500, {"reason": "M_UNKNOWN", "info": "Internal Server Error"}
            )

    def _send_error(self, request: Request, status: int, content: JsonDict) -> None:
        request.setResponseCode(status)
        request.setHeader("Content-Type", "application/json")
        res = _dict_to_json_bytes(content)
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


def get_media_metadata_from_request(
    request: Request, crypto_handler: CryptoHandler
) -> Tuple[str, JsonDict]:
    assert request.content is not None
    body = request.content.read().decode("ascii")

    try:
        parsed_body = json.loads(body)
    except json.decoder.JSONDecodeError as e:
        raise ContentScannerRestError(400, ErrCodes.MALFORMED_JSON, str(e))

    if not isinstance(parsed_body, dict):
        raise ContentScannerRestError(
            400,
            ErrCodes.MALFORMED_JSON,
            "Body must be a dictionary",
        )

    encrypted_body: Optional[JsonDict] = parsed_body.get("encrypted_body")
    if encrypted_body is not None:
        # If we have an encrypted payload in the body, decrypt it before doing
        # anything else.
        metadata = crypto_handler.decrypt_body(
            ciphertext=encrypted_body["ciphertext"],
            mac=encrypted_body["mac"],
            ephemeral=encrypted_body["ephemeral"],
        )
    else:
        # Otherwise, use the request's body since it will include the metadata in
        # clear text.
        metadata = parsed_body

    validate_encrypted_file_metadata(metadata)

    url = metadata["file"]["url"]
    media_path = url[len("mxc://") :]
    set_media_path_in_context(media_path)

    return media_path, metadata
