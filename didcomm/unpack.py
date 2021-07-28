from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.message import Message
from didcomm.types.types import JSON
from didcomm.types.unpack_opt import UnpackOpts
from didcomm.types.unpack_result import UnpackResult, Metadata


class Unpacker:

    def __init__(self,
                 unpack_opts: UnpackOpts = None,
                 secrets_resolver: SecretsResolver = None,
                 did_resolver: DIDResolver = None):
        pass

    async def unpack(self, msg: JSON) -> UnpackResult:
        return UnpackResult(
            msg=Message(payload={}, id="", type=""),
            metadata=Metadata(),
            signed_payload=None
        )
