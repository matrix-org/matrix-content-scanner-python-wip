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
from binascii import unhexlify
from typing import Optional

from matrix_content_scanner.config import MatrixContentScannerConfig
from matrix_content_scanner.mcs import MatrixContentScanner
from matrix_content_scanner.utils.types import JsonDict

SMALL_PNG = unhexlify(
    b"89504e470d0a1a0a0000000d4948445200000001000000010806"
    b"0000001f15c4890000000a49444154789c63000100000500010d"
    b"0a2db40000000049454e44ae426082"
)


def get_content_scanner(config: Optional[JsonDict] = None) -> MatrixContentScanner:
    if config is None:
        config = {
            "scan": {
                "script": "true",
                "temp_directory": "temp",
            },
            "web": {
                "host": "127.0.0.1",
                "port": 8080,
            },
            "crypto": {
                "pickle_path": "mcs_pickle.txt",
                "pickle_key": "foo",
            },
        }

    return MatrixContentScanner(MatrixContentScannerConfig(config))
