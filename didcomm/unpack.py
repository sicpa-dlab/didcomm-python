from __future__ import annotations

from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.message import Message
from didcomm.types.mtc import MTC
from didcomm.types.types import JSON
from didcomm.types.unpack_result import UnpackResult, Metadata


class Unpacker:
    async def unpack(self, msg: JSON) -> UnpackResult:
        return UnpackResult(
            msg=Message(payload={}, id="", type=""),
            metadata=Metadata(),
            signed_payload=None
        )


class UnpackBuilder:

    def finalize(self) -> Unpacker:
        return Unpacker()

    def did_resolver(self, did_resolver: DIDResolver) -> UnpackBuilder:
        return self

    def secrets_resolver(self, secrets_resolver: SecretsResolver) -> UnpackBuilder:
        return self

    def mtc(self, mtc: MTC) -> UnpackBuilder:
        return self

    def is_forward(self, value: bool = False) -> UnpackBuilder:
        return self
