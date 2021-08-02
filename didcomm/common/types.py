from __future__ import annotations

from typing import Dict, Any, Union, List

JSON_DATA = Union[Dict[str, Any], List[Any]]
JSON = str
JWK = str
JWT = str
JWS = Dict[str, Any]
JWE = Dict[str, Any]
DID = str
KID = str
DID_OR_KID = Union[DID, KID]
