from __future__ import annotations

from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.message import Message
from didcomm.types.mtc import MTC
from didcomm.types.types import JSON
from didcomm.types.unpack_result import UnpackResult, Metadata


class Unpacker:

    def __init__(self, mtc: MTC = None, is_forward: bool = False,
                 secrets_resolver: SecretsResolver = None, did_resolver: DIDResolver = None) -> None:
        pass

    async def unpack(self, msg: JSON) -> UnpackResult:
        return UnpackResult(
            msg=Message(payload={}, id="", type=""),
            metadata=Metadata(),
            signed_payload=None
        )
