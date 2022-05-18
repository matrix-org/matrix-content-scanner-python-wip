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
import json
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from twisted.internet.error import DNSLookupError
from twisted.web.client import Agent, readBody
from twisted.web.http_headers import Headers
from twisted.web.iweb import IResponse

from matrix_content_scanner import logging
from matrix_content_scanner.utils.constants import ErrCodes
from matrix_content_scanner.utils.errors import (
    ContentScannerRestError,
    WellKnownDiscoveryError,
)
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
    MEDIA_THUMBNAIL_PREFIX = "_matrix/media/%s/thumbnail"

    def __init__(self, mcs: "MatrixContentScanner"):
        self._base_url = mcs.config.scan.base_homeserver_url
        self._agent = Agent(mcs.reactor)
        self._well_known_cache: Dict[str, Optional[str]] = {}

    async def download_file(
        self,
        media_path: str,
        thumbnail_params: Optional[Dict[str, List[str]]] = None,
    ) -> MediaDescription:
        """Retrieve the file with the given `server_name/media_id` path, and stores it on
        disk.

        Args:
            media_path: The path identifying the media to retrieve.
            thumbnail_params: If present, then we want to request and scan a thumbnail
                generated with the provided parameters instead of the full media.

        Returns:
            A description of the file (including its full content).

        Raises:
            ContentScannerRestError: The file was not found or could not be downloaded due to an
                error on the remote homeserver's side.
        """
        url = await self._build_https_url(media_path, thumbnail_params=thumbnail_params)

        # Attempt to retrieve the file at the generated URL.
        try:
            file = await self._get_file_content(url)
        except _MediaNotFoundException:
            # If the file could not be found, it might be because the homeserver hasn't
            # been upgraded to a version that supports Matrix v1.1 endpoints yet, so try
            # again with an r0 endpoint.
            logger.info("File not found, trying legacy r0 path")

            url = await self._build_https_url(
                media_path, endpoint_version="r0", thumbnail_params=thumbnail_params
            )

            try:
                file = await self._get_file_content(url)
            except _MediaNotFoundException:
                # If that still failed, raise an error.
                raise ContentScannerRestError(
                    http_status=502,
                    reason=ErrCodes.REQUEST_FAILED,
                    info="File not found",
                )

        return file

    async def _build_https_url(
        self,
        media_path: str,
        endpoint_version: str = "v3",
        thumbnail_params: Optional[Dict[str, List[str]]] = None,
    ) -> str:
        """Turn a `server_name/media_id` path into an https:// one we can use to fetch
        the media.

        Note that if `base_homeserver_url` is set to an http URL, it will not be turned
        into an https one.

        Args:
            media_path: The media path to translate.
            endpoint_version: The version of the download endpoint to use. As of Matrix
                v1.1, this is either "v3" or "r0".
            thumbnail_params: If present, then we want to request and scan a thumbnail
                generated with the provided parameters instead of the full media.

        Returns:
            An https URL to use. If `base_homeserver_url` is set in the config, this
            will be used as the base of the URL.
        """
        server_name, media_id = media_path.split("/")[-2:]

        base_url = None
        if self._base_url is not None:
            base_url = self._base_url
        else:
            try:
                base_url = await self._discover_via_well_known(server_name)
            except WellKnownDiscoveryError as e:
                logger.info("Failed to discover server via well-known: %s", e)

        if base_url is None:
            base_url = "https://" + server_name

        prefix = self.MEDIA_DOWNLOAD_PREFIX
        query = None
        if thumbnail_params is not None:
            prefix = self.MEDIA_THUMBNAIL_PREFIX

            query = ""
            for key, items in thumbnail_params.items():
                for item in items:
                    query += "%s=%s&" % (key, item)
            query = query[:-1]

        path_prefix = prefix % endpoint_version

        url = "%s/%s/%s/%s" % (base_url, path_prefix, server_name, media_id)
        if query is not None:
            url += "?%s" % query

        return url

    async def _get_file_content(self, url: str) -> MediaDescription:
        """Retrieve the content of the file at a given URL.

        Args:
            url: The URL to query.

        Returns:
            A description of the file (including its full content).

        Raises:
            _MediaNotFoundException: the server returned a non-200 status that's not a
                5xx error.
            ContentScannerRestError: the server returned a 5xx status.
        """
        logger.info("Fetching file at URL: %s", url)

        code, body, headers = await self._get(url)

        logger.info("Remote server responded with %d", code)

        # If the response isn't a 200 OK, raise.
        if 200 < code:
            logger.info("Response body: %s", body)
            # If the response is a 404 or an "unrecognised request" à la Synapse,
            # consider that we could not find the media.
            if code == 400:
                try:
                    err = json.loads(body)
                    if err["errcode"] == "M_UNRECOGNIZED":
                        raise _MediaNotFoundException
                except (json.decoder.JSONDecodeError, KeyError):
                    pass

            if code == 404:
                raise _MediaNotFoundException

            raise ContentScannerRestError(
                502,
                ErrCodes.REQUEST_FAILED,
                "The remote server responded with an error",
            )

        content_type_headers = headers.getRawHeaders("content-type")

        if content_type_headers is None or len(content_type_headers) != 1:
            raise ContentScannerRestError(
                502,
                ErrCodes.REQUEST_FAILED,
                "The remote server responded with an invalid amount of Content-Type headers",
            )

        return MediaDescription(
            content_type=content_type_headers[0],
            content=body,
        )

    async def _discover_via_well_known(self, domain: str) -> Optional[str]:
        """Try to discover the base URL for the given domain via .well-known client
        discovery.

        Args:
            domain: The domain to discover the base URL for.

        Returns:
            The base URL to use, or None if no .well-known client file exist for this
            domain.

        Raises:
            WellKnownDiscoveryError if an error happened during the discovery attempt.
            twisted.internet.error.DNSLookupError if either the domain or the base URL it
                advertises can't be reached.
        """
        if domain in self._well_known_cache:
            logger.info("Fetching well-known result from cache")
            return self._well_known_cache[domain]

        url = f"https://{domain}/.well-known/matrix/client"
        logger.info("Fetching well-known at %s", url)

        code, body, _ = await self._get(url)

        if code != 200:
            if code == 404:
                self._well_known_cache[domain] = None
                return None

            raise WellKnownDiscoveryError(
                f"Server responded with non-200 status {code}"
            )

        try:
            parsed_body = json.loads(body)
        except json.decoder.JSONDecodeError as e:
            raise WellKnownDiscoveryError(e)

        try:
            base_url: str = parsed_body["m.homeserver"]["base_url"]
        except (KeyError, TypeError):
            raise WellKnownDiscoveryError("Response did not include a usable URL")

        if base_url.endswith("/"):
            base_url = base_url[:-1]

        url = base_url + "/_matrix/client/versions"
        code, _, _ = await self._get(url)

        if code != 200:
            raise WellKnownDiscoveryError(
                "Base URL does not seem to point to a working homeserver"
            )

        # Cache and return the result.
        self._well_known_cache[domain] = base_url
        return base_url

    async def _get(self, url: str) -> Tuple[int, bytes, Headers]:
        try:
            resp: IResponse = await self._agent.request(b"GET", url.encode("ascii"))
        except DNSLookupError:
            raise ContentScannerRestError(
                502,
                ErrCodes.REQUEST_FAILED,
                "Failed to reach the remote server",
            )

        return resp.code, await readBody(resp), resp.headers
