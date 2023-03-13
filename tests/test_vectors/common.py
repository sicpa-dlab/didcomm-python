from dataclasses import dataclass
from typing import Any

from didcomm.common.types import JSON, DID
from didcomm import Metadata

ALICE_DID = DID("did:example:alice")
BOB_DID = DID("did:example:bob")
CHARLIE_DID = DID("did:example:charlie")
DAVE_DID = DID("did:example:dave")


# Note. additional prefix `T` is to hide the clases
#       from pytest tests collector


@dataclass
class TTestVector:
    value: JSON
    metadata: Metadata


@dataclass
class TTestVectorNegative:
    value: JSON
    exc: Any
