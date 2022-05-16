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
import contextvars
import logging
from typing import Any, Tuple

media_path = contextvars.ContextVar("media_path")


class ContextLoggingAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: Any) -> Tuple[str, Any]:
        try:
            value = media_path.get()
            msg = "%s - %s" % (value, msg)
        except LookupError:
            pass

        return msg, kwargs


def getLogger(name: str) -> ContextLoggingAdapter:
    return ContextLoggingAdapter(logging.getLogger(name), None)


def set_media_path(v: bytes) -> None:
    media_path.set(v.decode("utf-8"))