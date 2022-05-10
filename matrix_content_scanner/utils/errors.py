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
from matrix_content_scanner.utils.constants import ErrCodes


class ContentScannerRestError(Exception):
    """
    Handled by the jsonwrap wrapper. Any servlets that don't use this
    wrapper should catch this exception themselves.
    """

    def __init__(self, http_status: int, reason: str, info: str) -> None:
        super(Exception, self).__init__(info)
        self.http_status = http_status
        self.reason = reason
        self.info = info


class FileDirtyError(ContentScannerRestError):
    def __init__(self) -> None:
        super(FileDirtyError, self).__init__(
            http_status=403,
            reason=ErrCodes.NOT_CLEAN,
            info="***VIRUS DETECTED***",
        )
