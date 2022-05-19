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
import copy
import unittest

from matrix_content_scanner.utils.constants import ErrCodes
from matrix_content_scanner.utils.encrypted_file_metadata import (
    validate_encrypted_file_metadata,
)
from matrix_content_scanner.utils.errors import ContentScannerRestError
from matrix_content_scanner.utils.types import JsonDict

BASE_METADATA: JsonDict = {
    "file": {
        "v": "v2",
        "key": {
            "alg": "A256CTR",
            "ext": True,
            "k": "F3miZm2vZhucJ062AuKMUwmd-O6AK0AXP29p4MKtq3Q",
            "key_ops": ["decrypt", "encrypt"],
            "kty": "oct",
        },
        "iv": "rJqtSdi3F/EAAAAAAAAAAA",
        "hashes": {"sha256": "NYvGRRQGfyWpXSUpba+ozSbehFP6kw5ZDg0xMppyX8c"},
        "url": "mxc://foo/bar",
    }
}


class EncryptedMetadataValidationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.metadata = copy.deepcopy(BASE_METADATA)

    def test_validate(self) -> None:
        validate_encrypted_file_metadata(BASE_METADATA)

    def test_bad_key_ops(self) -> None:
        self.metadata["file"]["key"]["key_ops"] = ["foo"]
        self._test_fails_validation()

    def test_no_file(self) -> None:
        self.metadata = {"foo": "bar"}
        self._test_fails_validation()

    def test_no_key(self) -> None:
        del self.metadata["file"]["key"]
        self._test_fails_validation()

    def test_no_iv(self) -> None:
        del self.metadata["file"]["iv"]
        self._test_fails_validation()

    def test_no_url(self) -> None:
        del self.metadata["file"]["url"]
        self._test_fails_validation()

    def test_no_hashes(self) -> None:
        del self.metadata["file"]["hashes"]
        self._test_fails_validation()

    def test_no_sha256(self) -> None:
        del self.metadata["file"]["hashes"]["sha256"]
        self._test_fails_validation()

    def test_no_k(self) -> None:
        del self.metadata["file"]["key"]["k"]
        self._test_fails_validation()

    def _test_fails_validation(self) -> None:
        with self.assertRaises(ContentScannerRestError) as cm:
            validate_encrypted_file_metadata(self.metadata)

        self.assertEqual(cm.exception.http_status, 400)
        self.assertEqual(cm.exception.reason, ErrCodes.MALFORMED_JSON)
