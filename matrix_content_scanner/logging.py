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
import logging
from contextvars import ContextVar
from typing import Any, Optional, Tuple

from twisted.web.http import Request

media_path: ContextVar[str] = ContextVar("media_path")
request_type: ContextVar[str] = ContextVar("request_type")


class ContextLoggingAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: Any) -> Tuple[str, Any]:
        kwargs.setdefault("extra", {})["media_path"] = _maybe_get_contextvar(media_path)
        kwargs.setdefault("extra", {})["request_type"] = _maybe_get_contextvar(
            request_type
        )

        return msg, kwargs


def _maybe_get_contextvar(var: ContextVar[str]) -> Optional[str]:
    try:
        return var.get()
    except LookupError:
        pass

    return None


def getLogger(name: str) -> ContextLoggingAdapter:
    return ContextLoggingAdapter(logging.getLogger(name), None)


def set_context_from_request(request: Request) -> None:
    assert request.path is not None
    path = request.path.decode("utf-8")
    # We're only interested in the bit *after* /_matrix/media_proxy/unstable
    parts = path.split("/")[4:]

    request_type.set(parts[0])
    if len(parts) == 3:
        media_path.set("/".join(parts[1:]))


def set_media_path(v: str) -> None:
    media_path.set(v)
