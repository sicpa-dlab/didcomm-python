from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from didcomm.common.algorithms import AuthCryptAlg, AnonCryptAlg
from didcomm.common.types import JSON, DID_OR_DID_URL
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.plaintext import Plaintext
from didcomm.secrets.secrets_resolver import SecretsResolver


@dataclass(frozen=True)
class PackResult:
    packed_msg: JSON
    service_endpoint: Optional[str]


@dataclass(frozen=True)
class PackConfig:
    secrets_resolver: SecretsResolver = None
    did_resolver: DIDResolver = None
    enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW
    enc_alg_anon: AnonCryptAlg = AnonCryptAlg.XC20P_ECDH_ES_A256KW
    encryption: bool = True
    authentication: bool = True
    non_repudiation: bool = False
    anonymous_sender: bool = True
    forward: bool = True


async def pack(plaintext: Plaintext, pack_config: Optional[PackConfig] = None,
         frm_enc: Optional[DID_OR_DID_URL] = None,
         frm_sign: Optional[DID_OR_DID_URL] = None,
         to: Optional[DID_OR_DID_URL] = None) -> PackResult:
    """
    Packs the message according to the given Pack Config.

    :raises FromEncryptNotSet: if the message needs to be encrypted and the sender DID or keyID for encryption is set
    in neither `frm_enc` argument nor `from` header in Plaintext
    :raises FromSignNotSet: if the message needs to be signed (non-repudiation is required) and the sender DID or keyID
    for signing is set in neither `frm_enc` argument nor `from` header in Plaintext
    :raises UnknownSenderException: if the sender DID or keyID can not be resolved
    :raises UnknownRecipientException: if the target DID or keyID can not be resolved
    :raises IncompatibleKeysException: if the sender and target keys are not compatible

    :param pack_config: configuration defining how pack needs to be done.
    If not specified - default configuration is used.
    :param frm_enc: an optional sender's DID or keyID to be used for encryption.
    If not specified, then `from` header in Plaintext is used.
    :param frm_sign: an optional DID or keyID to be used for signing (non-repudiation).
    If not specified, then `from` header in Plaintext is used.
    :param to: an optional recipient DID. If not specified, then `to` header in Plaintext is used.
    :return: a pack result consisting of a packed message as a JSON string
    and an optional service endpoint to be used in transport.
    """
    return PackResult(packed_msg="", service_endpoint="")
