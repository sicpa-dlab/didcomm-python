from dataclasses import dataclass

from didcomm.common.types import JSON
from didcomm.unpack import Metadata

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CHARLIE_DID = "did:example:charlie"


@dataclass
class TestVector:
    value: JSON
    metadata: Metadata
