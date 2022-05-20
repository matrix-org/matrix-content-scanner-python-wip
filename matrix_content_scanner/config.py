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
from typing import Any, Dict, List, Optional

import attr

from matrix_content_scanner.utils.errors import ConfigError


@attr.s(auto_attribs=True, frozen=True)
class WebConfig:
    host: str
    port: int


@attr.s(auto_attribs=True, frozen=True)
class ScanConfig:
    script: str
    temp_directory: str
    base_homeserver_url: Optional[str] = None
    do_not_cache_exit_codes: Optional[List[int]] = None
    removal_command: str = "rm"
    allowed_mimetypes: Optional[List[str]] = None


@attr.s(auto_attribs=True, frozen=True)
class CryptoConfig:
    pickle_path: str
    pickle_key: str


class MatrixContentScannerConfig:
    REQUIRED_SETTINGS = [
        "web.host",
        "web.port",
        "scan.script",
        "scan.temp_directory",
        "crypto.pickle_path",
        "crypto.pickle_key",
    ]

    def __init__(self, config_dict: Dict[str, Any]):
        if not isinstance(config_dict, dict):
            raise ConfigError("Bad configuration format")

        self._check_required(config_dict)

        self.web = WebConfig(**(config_dict.get("web") or {}))
        self.scan = ScanConfig(**(config_dict.get("scan") or {}))
        self.crypto = CryptoConfig(**(config_dict.get("crypto") or {}))

    def _check_required(self, config_dict: Dict[str, Any]) -> None:
        for setting in self.REQUIRED_SETTINGS:
            try:
                self._get_nested_property_at_key(config_dict, setting)
            except KeyError:
                raise ConfigError("Missing configuration setting %s" % setting)

    def _get_nested_property_at_key(self, d: Dict[str, Any], key: str) -> Any:
        parts = key.split(".")
        prop = d[parts[0]]

        if len(parts) == 1:
            return prop

        if not isinstance(prop, dict):
            raise ConfigError(
                "Expected configuration property %s to be a dictionary" % parts[0],
            )

        return self._get_nested_property_at_key(prop, ".".join(parts[1:]))
