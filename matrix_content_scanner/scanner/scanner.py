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
import os.path
import subprocess
from typing import TYPE_CHECKING, Dict, List, Optional

import attr
from mautrix.crypto.attachments import decrypt_attachment
from mautrix.errors import DecryptionError
from mautrix.util import magic

from matrix_content_scanner import logging
from matrix_content_scanner.utils.constants import ErrCodes
from matrix_content_scanner.utils.errors import ContentScannerRestError, FileDirtyError
from matrix_content_scanner.utils.types import JsonDict, MediaDescription

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner

logger = logging.getLogger(__name__)


@attr.s(auto_attribs=True, frozen=True)
class CacheEntry:
    result: bool
    media: Optional[MediaDescription] = None
    info: Optional[str] = None


class Scanner:
    def __init__(self, mcs: "MatrixContentScanner"):
        self._file_downloader = mcs.file_downloader
        self._script = mcs.config.scan.script
        self._result_cache: Dict[str, CacheEntry] = {}
        self._exit_codes_to_ignore = mcs.config.scan.do_not_cache_exit_codes
        self._removal_command = mcs.config.scan.removal_command
        self._store_directory = os.path.abspath(mcs.config.scan.temp_directory)
        self._allowed_mimetypes = mcs.config.scan.allowed_mimetypes

    async def scan_file(
        self,
        media_path: str,
        metadata: Optional[JsonDict] = None,
        thumbnail_params: Optional[Dict[str, List[str]]] = None,
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
        cache_key = self._get_cache_key_for_file(media_path, metadata, thumbnail_params)

        # Return the cached result if there's one.
        if cache_key in self._result_cache:
            cache_entry = self._result_cache[cache_key]
            logger.info("Returning cached result %s", cache_entry.result)

            if cache_entry.result is False:
                # If we defined additional info when caching the error, feed that into
                # the new error.
                if cache_entry.info is not None:
                    raise FileDirtyError(info=cache_entry.info)
                else:
                    raise FileDirtyError()
            else:
                if cache_entry.media is not None:
                    return cache_entry.media

                logger.warning(
                    "Result cache is confused: missing media but result is True.",
                )

        # Download the file, and decrypt it if necessary.
        media = await self._file_downloader.download_file(
            media_path=media_path,
            thumbnail_params=thumbnail_params,
        )

        if metadata is not None:
            # If the file is encrypted, we need to decrypt it before we can scan it, but
            # we also need to keep the encrypted body in memory in case we want to return
            # it to the client.
            clear_media = MediaDescription(
                content=self._decrypt_file(media.content, metadata),
                content_type="",
            )
        else:
            clear_media = media

        try:
            self._check_mimetype(
                media=clear_media,
                encrypted=metadata is not None,
            )
        except FileDirtyError as e:
            self._result_cache[cache_key] = CacheEntry(
                result=False,
                info=e.info,
            )
            raise

        try:
            file_path = self._write_file_to_disk(media_path, clear_media.content)
        except FileDirtyError as e:
            self._result_cache[cache_key] = CacheEntry(
                result=False,
                info=e.info,
            )
            raise

        exit_code = self._run_scan(file_path)
        result = exit_code == 0

        # If the exit code isn't part of the ones we should ignore, cache the result.
        if (
            self._exit_codes_to_ignore is None
            or exit_code not in self._exit_codes_to_ignore
        ):
            logger.info("Caching result %s", result)

            if result is False:
                # Don't cache the bad file, otherwise we might end up using lots of memory
                # for data we don't need.
                media = None

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
        thumbnail_params: Optional[Dict[str, List[str]]],
    ) -> str:
        """Generates the key to use to store the result for the given media in the result
        cache.

        The key is computed using the media's `server_name/media_id` path, but also the
        metadata dict (stringified), in case e.g. the decryption key changes, as well as
        the parameters used to generate the thumbnail if any (stringified), to
        differentiate thumbnails from full-sized media.
        The resulting key is a sha256 hash of the concatenation of these two values.

        Args:
            media_path: The `server_name/media_id` path of the file to scan.
            metadata: The file's metadata (or None if the file isn't encrypted).
            thumbnail_params: The parameters to generate thumbnail with. If no parameter
                is passed, this will be an empty dict. If the media being requested is not
                a thumbnail, this will be None.
        """
        raw_metadata = json.dumps(metadata)
        raw_params = json.dumps(thumbnail_params)
        base_string = media_path + raw_metadata + raw_params

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

        Raises:
            FileDirtyError if the media path is malformed in a way that would cause the
                file to be written outside of the configured directory.
        """
        # Figure out the full absolute path for this file. Given _store_directory is
        # already an absolute path we likely already have an absolute path, but we want to
        # make sure we don't have any '..' etc in the full path, to make sure we don't try
        # to write outside the directory.
        full_path = os.path.abspath(os.path.join(self._store_directory, media_path))
        if not full_path.startswith(self._store_directory):
            raise FileDirtyError("Malformed media ID")

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

    def _check_mimetype(self, media: MediaDescription, encrypted: bool) -> None:
        mimetype = magic.mimetype(media.content)

        logger.info("File is %s", mimetype)

        if encrypted is False and mimetype != media.content_type:
            # Error if the MIME type isn't matching the one that's expected, but only if
            # the file is not encrypted (because otherwise we'll always have
            # 'application/octet-stream' in the Content-Type header).
            logger.error(
                "Mismatching MIME type (%s) and Content-Type header (%s)",
                mimetype,
                media.content_type,
            )
            raise FileDirtyError("File type not supported")

        if (
            self._allowed_mimetypes is not None
            and mimetype not in self._allowed_mimetypes
        ):
            logger.error(
                "MIME type for file is forbidden: %s",
                mimetype,
            )
            raise FileDirtyError("File type not supported")
