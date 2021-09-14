from dataclasses import dataclass
from typing import Any

from didcomm.common.types import JSON
from didcomm.unpack import Metadata

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CHARLIE_DID = "did:example:charlie"


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
