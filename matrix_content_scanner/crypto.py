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
import logging
from typing import TYPE_CHECKING

from olm.pk import PkDecryption, PkMessage

from matrix_content_scanner.utils.types import JsonDict

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


logger = logging.getLogger(__name__)


class CryptoHandler:
    def __init__(self, mcs: "MatrixContentScanner") -> None:
        key = mcs.config.crypto.pickle_key
        path = mcs.config.crypto.pickle_path
        try:
            with open(path, "r") as fp:
                pickle = fp.read()

            self._decryptor: PkDecryption = PkDecryption.from_pickle(
                pickle=pickle.encode("ascii"),
                passphrase=key,
            )

            logger.info("Loaded Olm pickle from %s", path)
        except FileNotFoundError:
            self._decryptor = PkDecryption()
            pickle_bytes = self._decryptor.pickle(passphrase=key)

            logger.info(
                "Olm pickle not found, generating one and saving it at %s", path
            )

            with open(path, "w+") as fp:
                fp.write(pickle_bytes.decode("ascii"))

    def get_public_key(self) -> str:
        return self._decryptor.public_key

    def decrypt_body(self, ciphertext: str, mac: str, ephemeral: str) -> JsonDict:
        msg = PkMessage(
            ephemeral_key=ephemeral,
            mac=mac,
            ciphertext=ciphertext,
        )

        decrypted = self._decryptor.decrypt(msg)

        # We know that the decrypted payload will parse as bytes,
        return json.loads(decrypted)  # type: ignore[no-any-return]
