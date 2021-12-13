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
import logging
import os
import os.path
from typing import TYPE_CHECKING, Optional

from matrix_common.json import JsonDict
from matrix_common.servlet import MatrixRestError
from mautrix.crypto.attachments import decrypt_attachment
from twisted.web.client import Agent, readBody
from twisted.web.iweb import IResponse

from matrix_content_scanner.utils import ErrCodes

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner

logger = logging.getLogger(__name__)


class _MediaNotFoundException(Exception):
    """An exception raised to signal that a URL could not be found on the remote
    homeserver.
    """

    pass


class FileDownloader:
    MEDIA_DOWNLOAD_PREFIX = "_matrix/media/%s/download"

    def __init__(self, mcs: "MatrixContentScanner"):
        self._base_url = mcs.config.scan.base_homeserver_url
        self._agent = Agent(mcs.reactor)
        self._store_directory = mcs.config.scan.temp_directory

    async def download_file(self, media_path: str, metadata: Optional[JsonDict]) -> str:
        """Retrieve the file with the given `server_name/media_id` path, and stores it on
        disk.

        Args:
            media_path: The path identifying the media to retrieve.
            metadata: The metadata attached to the file (e.g. thumbnail sources,
                decryption key), or None if the file isn't encrypted.

        Returns:
            The path to the file on disk.

        Raises:
            MatrixRestError: The file was not found or could not be downloaded due to an
                error on the remote homeserver's side.
        """
        url = self._build_https_url(media_path)

        # Attempt to retrieve the file at the generated URL.
        try:
            body = await self._get_file_content(url)
        except _MediaNotFoundException:
            # If the file could not be found, it might be because the homeserver hasn't
            # been upgraded to a version that supports Matrix v1.1 endpoints yet, so try
            # again with an r0 endpoint.
            logger.info("File not found, trying legacy r0 path")

            url = self._build_https_url(media_path, endpoint_version="r0")

            try:
                body = await self._get_file_content(url)
            except _MediaNotFoundException:
                # If that still failed, raise an error.
                raise MatrixRestError(404, ErrCodes.FILE_NOT_FOUND, "File not found")

        if metadata is not None:
            body = self._decrypt_file(body, metadata)

        return self._write_file_to_disk(media_path, body)

    def _decrypt_file(self, body: bytes, metadata: JsonDict) -> bytes:
        """Extract decryption information from the file's metadata and decrypt it.

        Args:
            body: The encrypted body of the file.
            metadata: The part of the request that includes decryption information.

        Returns:
            The decrypted content of the file.
        """
        logger.info("File is encrypted, decrypting")

        # TODO: validate schema
        key = metadata["file"]["key"]["k"]
        hash = metadata["file"]["hashes"]["sha256"]
        iv = metadata["file"]["iv"]

        # TODO: Handle EncryptionError from mautrix
        return decrypt_attachment(body, key, hash, iv)

    def _build_https_url(self, media_path: str, endpoint_version: str = "v3") -> str:
        """Turn a `server_name/media_id` path into an https:// one we can use to fetch
        the media.

        Note that if `base_homeserver_url` is set to an http URL, it will not be turned
        into an https one.

        Args:
            media_path: The media path to translate.
            endpoint_version: The version of the download endpoint to use. As of Matrix
                v1.1, this is either "v3" or "r0".

        Returns:
            An https URL to use. If `base_homeserver_url` is set in the config, this
            will be used as the base of the URL.
        """
        server_name, media_id = media_path.split("/")[-2:]

        # FIXME: We currently use the server name directly to fetch a media if no base
        #   URL has been provided. Ideally in this case we should be figuring out which
        #   hostname to hit using well-known resolution.
        base_url = "https://" + server_name
        if self._base_url is not None:
            base_url = self._base_url

        path_prefix = self.MEDIA_DOWNLOAD_PREFIX % endpoint_version

        return "%s/%s/%s/%s" % (base_url, path_prefix, server_name, media_id)

    async def _get_file_content(self, url: str) -> bytes:
        """Retrieve the content of the file at a given URL.

        Args:
            url: The URL to query.

        Returns:
            The file's body.

        Raises:
            _MediaNotFoundException: the server returned a non-200 status that's not a
                5xx error.
            MatrixRestError: the server returned a 5xx status.
        """
        logger.info("Fetching file at URL: %s", url)

        resp: IResponse = await self._agent.request(b"GET", url.encode("ascii"))

        logger.info("Remote server responded with %d", resp.code)

        # If the response isn't a 200 OK but isn't a 5xx, consider that the media
        # couldn't be found.
        if 200 < resp.code < 500:
            raise _MediaNotFoundException

        if resp.code >= 500:
            raise MatrixRestError(
                502,
                ErrCodes.UNKNOWN,
                "The remote server experienced an unknown error",
            )

        return await readBody(resp)

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
