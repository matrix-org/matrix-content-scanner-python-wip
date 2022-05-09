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
from typing import TYPE_CHECKING

from twisted.web.client import Agent, readBody
from twisted.web.iweb import IResponse

from matrix_content_scanner.servlets import MatrixRestError
from matrix_content_scanner.utils.constants import ErrCodes
from matrix_content_scanner.utils.types import MediaDescription

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

    async def download_file(self, media_path: str) -> MediaDescription:
        """Retrieve the file with the given `server_name/media_id` path, and stores it on
        disk.

        Args:
            media_path: The path identifying the media to retrieve.

        Returns:
            A description of the file (including its full content).

        Raises:
            MatrixRestError: The file was not found or could not be downloaded due to an
                error on the remote homeserver's side.
        """
        url = self._build_https_url(media_path)

        # Attempt to retrieve the file at the generated URL.
        try:
            file = await self._get_file_content(url)
        except _MediaNotFoundException:
            # If the file could not be found, it might be because the homeserver hasn't
            # been upgraded to a version that supports Matrix v1.1 endpoints yet, so try
            # again with an r0 endpoint.
            logger.info("File not found, trying legacy r0 path")

            url = self._build_https_url(media_path, endpoint_version="r0")

            try:
                file = await self._get_file_content(url)
            except _MediaNotFoundException:
                # If that still failed, raise an error.
                raise MatrixRestError(404, ErrCodes.FILE_NOT_FOUND, "File not found")

        return file

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

    async def _get_file_content(self, url: str) -> MediaDescription:
        """Retrieve the content of the file at a given URL.

        Args:
            url: The URL to query.

        Returns:
            A description of the file (including its full content).

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

        content_type_headers = resp.headers.getRawHeaders("content-type")

        if content_type_headers is None or len(content_type_headers) != 1:
            raise MatrixRestError(
                502,
                ErrCodes.UNKNOWN,
                "The remote server responded with an invalid amount of Content-Type headers",
            )

        return MediaDescription(
            content_type=content_type_headers[0],
            content=await readBody(resp),
        )
