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
import hashlib
import json
import logging
import os.path
import subprocess
from typing import TYPE_CHECKING, Dict, List, Optional

import attr
from mautrix.crypto.attachments import decrypt_attachment
from mautrix.errors import DecryptionError

from matrix_content_scanner.servlets import JsonDict
from matrix_content_scanner.utils.constants import ErrCodes
from matrix_content_scanner.utils.errors import FileDirtyError, ContentScannerRestError
from matrix_content_scanner.utils.types import MediaDescription

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner

logger = logging.getLogger(__name__)


@attr.s(auto_attribs=True, frozen=True)
class CacheEntry:
    result: bool
    media: MediaDescription


class Scanner:
    def __init__(self, mcs: "MatrixContentScanner"):
        self._file_downloader = mcs.file_downloader
        self._script = mcs.config.scan.script
        self._result_cache: Dict[str, CacheEntry] = {}
        self._exit_codes_to_ignore = mcs.config.scan.do_not_cache_exit_codes
        self._removal_command = mcs.config.scan.removal_command
        self._store_directory = mcs.config.scan.temp_directory

    async def scan_file(
        self,
        media_path: str,
        metadata: Optional[JsonDict],
        thumbnail_params: Optional[Dict[bytes, List[bytes]]] = None,
    ) -> MediaDescription:
        """Download and scan the given media.

        Unless the scan fails with one of the codes listed in `do_not_cache_exit_codes`,
        also cache the result.

        If the file already has an entry in the result cache, return this value without
        downloading the file again.

        Args:
            media_path: The `server_name/media_id` path for the media.
            metadata: The metadata attached to the file (e.g. decryption key), or None if
                the file isn't encrypted.
            thumbnail_params: If present, then we want to request and scan a thumbnail
                generated with the provided parameters instead of the full media.

        Returns:
            A description of the media.

        Raises:
            ContentScannerRestError if the file could not be downloaded.
            FileDirtyError if the result of the scan said that the file is dirty.
        """
        # Compute the cache key for the media.
        # TODO: calculate the cache key with thumbnail params
        cache_key = self._get_cache_key_for_file(media_path, metadata)

        # Return the cached result if there's one.
        if cache_key in self._result_cache:
            cache_entry = self._result_cache[cache_key]
            logger.info("Returning cached result %s", cache_entry.result)

            if cache_entry.result is False:
                raise FileDirtyError()

            return cache_entry.media

        # Download the file, and decrypt it if necessary.
        media = await self._file_downloader.download_file(
            media_path=media_path,
            thumbnail_params=thumbnail_params,
        )

        if metadata is not None:
            # If the file is encrypted, we need to decrypt it before we can scan it, but
            # we also need to keep the encrypted body in memory in case we want to return
            # it to the client.
            decrypted_file_body = self._decrypt_file(media.content, metadata)
            file_path = self._write_file_to_disk(media_path, decrypted_file_body)
        else:
            file_path = self._write_file_to_disk(media_path, media.content)

        exit_code = self._run_scan(file_path)
        result = exit_code == 0

        # If the exit code isn't part of the ones we should ignore, cache the result.
        if (
            self._exit_codes_to_ignore is None
            or exit_code not in self._exit_codes_to_ignore
        ):
            logger.info("Caching result %s", result)
            self._result_cache[cache_key] = CacheEntry(
                result=result,
                media=media,
            )
        else:
            logger.info(
                "Scan returned exit code %d which must not be cached", exit_code
            )

        # Delete the file now that we've scanned it.
        logger.info("Scan has finished, removing file")
        removal_command_parts = self._removal_command.split()
        removal_command_parts.append(file_path)
        subprocess.run(removal_command_parts)

        # Raise an error if the result isn't clean.
        if result is False:
            raise FileDirtyError()

        return media

    def _get_cache_key_for_file(
        self,
        media_path: str,
        metadata: Optional[JsonDict],
    ) -> str:
        """Generates the key to use to store the result for the given media in the result
        cache.

        The key is computed using the media's `server_name/media_id` path, but also the
        metadata dict (stringified), in case e.g. the decryption key changes.
        The resulting key is a sha256 hash of the concatenation of these two values.

        Args:
            media_path: The `server_name/media_id` path of the file to scan.
            metadata: The file's metadata (or None if the file isn't encrypted).
        """
        raw_metadata = json.dumps(metadata)
        base_string = media_path + raw_metadata
        return hashlib.sha256(base_string.encode("ascii")).hexdigest()

    def _decrypt_file(self, body: bytes, metadata: JsonDict) -> bytes:
        """Extract decryption information from the file's metadata and decrypt it.

        Args:
            body: The encrypted body of the file.
            metadata: The part of the request that includes decryption information.

        Returns:
            The decrypted content of the file.
        """
        logger.info("File is encrypted, decrypting")

        # At this point the schema should have been validated so we can pull these values
        # out safely.
        key = metadata["file"]["key"]["k"]
        hash = metadata["file"]["hashes"]["sha256"]
        iv = metadata["file"]["iv"]

        try:
            return decrypt_attachment(body, key, hash, iv)
        except DecryptionError as e:
            raise ContentScannerRestError(
                http_status=400,
                reason=ErrCodes.FAILED_TO_DECRYPT,
                info=e.message,
            )


    def _write_file_to_disk(self, media_path: str, body: bytes) -> str:
        """Writes the given content to disk. The final file name will be a concatenation
        of `temp_directory` and the media's `server_name/media_id` path.

        Args:
            media_path: The `server_name/media_id` path of the media we're processing.
            body: The bytes to write to disk.

        Returns:
            The full path to the newly written file.
        """
        # Figure out the full absolute path for this file.
        full_path = os.path.abspath(os.path.join(self._store_directory, media_path))

        logger.info("Writing file to %s", full_path)

        # Create any directory we need.
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        with open(full_path, "wb") as fp:
            fp.write(body)

        return full_path

    def _run_scan(self, file_name: str) -> int:
        """Runs the scan script, passing it the given file name.

        Args:
            file_name: Name of the file to scan.

        Returns:
            The exit code the script returned.
        """
        try:
            subprocess.run([self._script, file_name], check=True)
            logger.info("Scan succeeded")
            return 0
        except subprocess.CalledProcessError as e:
            logger.info("Scan failed with exit code %d: %s", e.returncode, e.stderr)
            return e.returncode
