from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from didcomm.common.algorithms import AuthCryptAlg, AnonCryptAlg
from didcomm.common.types import JSON, DID_OR_DID_URL
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.plaintext import Plaintext, PlaintextOptionalHeaders
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
    anonymous_sender: bool = False
    forward: bool = True


@dataclass(frozen=True)
class PackParameters:
    forward_headers: Optional[PlaintextOptionalHeaders] = None


async def pack(plaintext: Plaintext,
               frm: DID_OR_DID_URL, to: DID_OR_DID_URL,
               sign_frm: Optional[DID_OR_DID_URL] = None,
               pack_config: Optional[PackConfig] = None,
               pack_params: Optional[PackParameters] = None) -> PackResult:
    """
    Packs the message to the given recipient.

    Pack is done according to the given Pack Config.
    Default config performs repudiable authentication encryption (auth_crypt)
    and prepares a message ready to be forwarded to the returned endpoint (via Forward protocol).

    It's possible to add non-repudiation by providing `sign_frm` DID or key ID.

    :raises InvalidArgument: if invalid input is provided.
    For example, if `frm` argument doesn't match `from` header in Plaintext,
    or `to` argument doesn't match any of `to` header values in Plaintext.
    :raises UnknownSenderException: if the sender DID or keyID can not be resolved
    :raises UnknownRecipientException: if the target DID or keyID can not be resolved
    :raises IncompatibleKeysException: if the sender and target keys are not compatible

    :param plaintext: the plaintext message to be packed
    :param frm: a DID or key ID the sender uses for authenticated encryption.
    Must match `from` header in Plaintext if the header is set.
    If authentication is not required by the provided 'pack_config', then any value can be passed to 'frm'.
    :param to: a target DID or key ID the plaintext will be encrypted for.
    Must match any of `to` header values in Plaintext if the header is set.
    :param sign_frm: if non-repudiation is needed, a DID or key ID to be used for signing must be specified.
    Not required by default as repudiation is expected in most of the cases.
    :param pack_config: configuration defining how pack needs to be done.
    If not specified - default configuration is used.
    :param pack_params: optional parameters for pack
    :return: a pack result consisting of a packed message as a JSON string
    and an optional service endpoint to be used to transport teh packed message.
    """
    return PackResult(packed_msg="", service_endpoint="")
