from __future__ import annotations

from typing import Optional, NamedTuple

from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.algorithms import AnonCryptAlg
from didcomm.types.message import Message
from didcomm.types.mtc import MTC
from didcomm.types.types import JSON, DID
from didcomm.types.unpack_result import UnpackResult, Metadata


class ForwardUnpackResult(NamedTuple):
    forward_unpack_result: Optional[UnpackResult]
    payload_unpack_result: UnpackResult


class Forwarder:

    def __init__(self, secrets_resolver: SecretsResolver = None, did_resolver: DIDResolver = None):
        pass

    async def forward(self, packed_msg: JSON, to_did: DID,
                      enc_alg: AnonCryptAlg) -> JSON:
        return ""

    async def unpack_forward(self, forward_msg: JSON) -> ForwardUnpackResult:
        return ForwardUnpackResult(
            forward_unpack_result=UnpackResult(
                msg=Message(payload={}, id="", type=""),
                metadata=Metadata(),
                signed_payload=None
            ),
            payload_unpack_result=UnpackResult(
                msg=Message(payload={}, id="", type=""),
                metadata=Metadata(),
                signed_payload=None
            )

        )

    @staticmethod
    def parse_forward_payload(unpack_result: UnpackResult) -> JSON:
        return ""

    @staticmethod
    def create_forward_mtc() -> MTC:
        return MTC(
            expect_anoncrypted=True,
            expect_signed=False,
            expect_authcrypted=False
        )
