from dataclasses import dataclass

from didcomm.common.types import JSON
from didcomm.message import Message
from didcomm.unpack import Metadata

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CHARLIE_DID = "did:example:charlie"

TEST_MESSAGE: Message = Message(
    id="1234567890",
    type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
    frm=ALICE_DID,
    to=[BOB_DID],
    created_time=1516269022,
    expires_time=1516385931,
    body={"messagespecificattribute": "and its value"},
)


@dataclass
class TestVector:
    value: JSON
    metadata: Metadata
