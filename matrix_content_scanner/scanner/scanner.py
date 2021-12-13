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
import subprocess
from typing import TYPE_CHECKING, Dict, Optional

from matrix_common.json import JsonDict

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner

logger = logging.getLogger(__name__)


class Scanner:
    def __init__(self, mcs: "MatrixContentScanner"):
        self._file_downloader = mcs.file_downloader
        self._script = mcs.config.scan.script
        self._result_cache: Dict[str, bool] = {}
        self._exit_codes_to_ignore = mcs.config.scan.do_not_cache_exit_codes
        self._removal_command = mcs.config.scan.removal_command

    async def scan_file(self, media_path: str, metadata: Optional[JsonDict]) -> bool:
        """Download and scan the given media.

        Unless the scan fails with one of the codes listed in `do_not_cache_exit_codes`,
        also cache the result.

        If the file already has an entry in the result cache, return this value without
        downloading the file again.

        Args:
            media_path: The `server_name/media_id` path for the media.
            metadata: The metadata attached to the file (e.g. thumbnail sources,
                decryption key), or None if the file isn't encrypted.

        Returns:
            Whether the scan succeeded, i.e. whether the script returned with a 0 exit
            code.
        """
        # Compute the cache key for the media.
        cache_key = self._get_cache_key_for_file(media_path, metadata)

        # Return the cached result if there's one.
        if cache_key in self._result_cache:
            logger.info("Returning cached result %s", self._result_cache[cache_key])
            return self._result_cache[cache_key]

        # Download and scan the file.
        file_path = await self._file_downloader.download_file(media_path, metadata)
        exit_code = self._run_scan(file_path)
        result = exit_code == 0

        # If the exit code isn't part of the ones we should ignore, cache the result.
        if (
            self._exit_codes_to_ignore is None
            or exit_code not in self._exit_codes_to_ignore
        ):
            logger.info("Scan returned exit code %d which must not be cached", exit_code)
            self._result_cache[cache_key] = result

        # Delete the file now that we've scanned it.
        logger.info("Scan has finished, removing file")
        removal_command_parts = self._removal_command.split()
        removal_command_parts.append(file_path)
        subprocess.run(removal_command_parts)

        return result

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

    def _run_scan(self, file_name: str) -> int:
        """Runs the scan script, passing it the given file name.

        Args:
            file_name: Name of the file to scan.

        Returns:
            The exit code the script returned.
        """
        try:
            subprocess.run([self._script, file_name])
            logger.info("Scan succeeded")
            return 0
        except subprocess.CalledProcessError as e:
            logger.info("Scan failed with exit code %d: %s", e.returncode, e.stderr)
            return e.returncode
