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
import json
import unittest

from olm.pk import PkEncryption

from matrix_content_scanner.servlets import _metadata_from_body
from matrix_content_scanner.utils.constants import ErrCodes
from matrix_content_scanner.utils.errors import ContentScannerRestError
from matrix_content_scanner.utils.types import JsonDict
from tests.testutils import ENCRYPTED_FILE_METADATA, get_content_scanner


class ServletUtilsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.crypto_handler = get_content_scanner().crypto_handler

    def test_unencrypted(self) -> None:
        body_bytes = json.dumps(ENCRYPTED_FILE_METADATA)
        metadata = _metadata_from_body(body_bytes, self.crypto_handler)
        self.assertEqual(metadata, ENCRYPTED_FILE_METADATA)

    def test_encrypted(self) -> None:
        encrypted_body = self._encrypt_body(ENCRYPTED_FILE_METADATA)
        body_bytes = json.dumps(encrypted_body)
        metadata = _metadata_from_body(body_bytes, self.crypto_handler)
        self.assertEqual(metadata, ENCRYPTED_FILE_METADATA)

    def test_bad_json(self) -> None:
        with self.assertRaises(ContentScannerRestError) as cm:
            _metadata_from_body("foo", self.crypto_handler)

        self.assertEqual(cm.exception.reason, ErrCodes.MALFORMED_JSON)

    def _encrypt_body(self, content: JsonDict) -> JsonDict:
        pke = PkEncryption(self.crypto_handler.public_key)
        plaintext = json.dumps(content)
        msg = pke.encrypt(plaintext)

        return {
            "encrypted_body": {
                "ciphertext": msg.ciphertext,
                "mac": msg.mac,
                "ephemeral": msg.ephemeral_key,
            }
        }
