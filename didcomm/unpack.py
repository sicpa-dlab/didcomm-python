from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.plaintext import Plaintext
from didcomm.types.types import JSON
from didcomm.types.unpack_opt import UnpackOpts
from didcomm.types.unpack_result import UnpackResult, Metadata


class Unpacker:
    """Unpacker of packed DIDComm messages."""

    def __init__(self,
                 secrets_resolver: SecretsResolver,
                 did_resolver: DIDResolver,
                 unpack_opts: UnpackOpts = UnpackOpts()):
        """Creates an Unpacker instance."""
        pass

    async def unpack(self, message: JSON) -> UnpackResult:
        """Unpacks the packed DIDComm message."""
        return UnpackResult(
            plaintext=Plaintext(id="", type="", body={}),
            metadata=Metadata(),
            signed_message=None
        )
