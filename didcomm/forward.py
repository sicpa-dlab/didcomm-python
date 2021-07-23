from didcomm.types.algorithms import EncAlgAnonCrypt, KWAlgAnonCrypt
from didcomm.types.types import JSON


async def forward(packed_msg: JSON, to_did: str,
                  enc: EncAlgAnonCrypt, alg: KWAlgAnonCrypt = KWAlgAnonCrypt.ECDH_ES_A256KW) -> JSON:
    return ""
