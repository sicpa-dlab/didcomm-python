from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from didcomm.common.algorithms import AuthCryptAlg, AnonCryptAlg
from didcomm.common.types import JSON, DID_OR_DID_URL
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.plaintext import Plaintext, PlaintextOptionalHeaders
from didcomm.secrets.secrets_resolver import SecretsResolver


@dataclass(frozen=True)
class PackResult:
    """
    Result of pack operation.

    Attributes:
        packed_msg (str): a packed message as a JSON string ready to be forwarded to the returned 'service_endpoint'
        service_endpoint (str): an optional service endpoint to be used to transport the 'packed_msg'.
    """
    packed_msg: JSON
    service_endpoint: Optional[str]


class AuthMode(Enum):
    AUTH_UNPROTECTED_SENDER = auto()
    AUTH_PROTECTED_SENDER = auto()
    NO_AUTH = auto()


@dataclass(frozen=True)
class PackConfig:
    """
    Pack configuration.

    Default config performs repudiable authentication encryption (auth_crypt)
    and prepares a message ready to be forwarded to the returned endpoint (via Forward protocol).

    Attributes:
        secrets_resolver (SecretsResolver): an optional secrets resolver that can override a default secrets resolver
        registered by 'register_default_secrets_resolver'

        did_resolver (DIDResolver): an optional DID Doc resolver that can override a default DID Doc resolver
        registered by 'register_default_did_resolver'

        enc_alg_auth (AuthCryptAlg): the encryption algorithm to be used for authentication encryption (auth_crypt).
        `A256CBC_HS512_ECDH_1PU_A256KW` by default.

        enc_alg_anon (AnonCryptAlg): the encryption algorithm to be used for anonymous encryption (anon_crypt).
        `XC20P_ECDH_ES_A256KW` by default.

        auth_mode (AuthMode): how authentication should be done: no authentication (NO_AUTH) to perform anon crypt,
        authentication with unprotected sender (AUTH_UNPROTECTED_SENDER) or
        authentication with protected sender (AUTH_PROTECTED_SENDER).

        forward (bool):  whether the packed messages need to be wrapped into Forward messages to be sent to Mediators
        as defined by the Forward protocol. True by default.
    """
    secrets_resolver: SecretsResolver = None
    did_resolver: DIDResolver = None
    enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW
    enc_alg_anon: AnonCryptAlg = AnonCryptAlg.XC20P_ECDH_ES_A256KW
    auth_mode: AuthMode = AuthMode.AUTH_UNPROTECTED_SENDER
    forward: bool = True


@dataclass(frozen=True)
class PackParameters:
    """
    Optional parameters for pack.

    Attributes:
        forward_headers (PlaintextOptionalHeaders): if forward is enabled (true by default),
        optional headers can be passed to the wrapping Forward messages.

        sign_frm (DID_OR_DID_URL): if non-repudiation is needed, a DID or key ID to be used for signing must be specified.
        Not required by default as repudiation is expected in most of the cases.
    """
    forward_headers: Optional[PlaintextOptionalHeaders] = None
    sign_frm: Optional[DID_OR_DID_URL] = None


async def pack(plaintext: Plaintext,
               frm: DID_OR_DID_URL, to: DID_OR_DID_URL,
               pack_config: Optional[PackConfig] = None,
               pack_params: Optional[PackParameters] = None) -> PackResult:
    """
    Packs the message to the given recipient.

    Pack is done according to the given Pack Config.
    Default config performs repudiable authentication encryption (auth_crypt)
    and prepares a message ready to be forwarded to the returned endpoint (via Forward protocol).

    It's possible to add non-repudiation by providing `sign_frm` argument in `pack_params` (DID or key ID).

    Encryption is done as following:
        - encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
        - if 'frm' is a DID, then the first sender's `keyAgreement` verification method is used for which
        a private key in the secrets resolver is found
        - if 'frm' is a key ID, then the sender's `keyAgreement` verification method identified by the given key ID is used.
        - if 'to' is a DID, then multiplex encryption is done for all keys from the receiver's `keyAgreement` verification relationship
        - if 'to' is a key ID, then encryption is done for the  receiver's `keyAgreement` verification method identified by the given key ID is used.

    If non-repudiation (signing) is used by specifying a `sign_frm` argument in `pack_params` (disabled by default):
        - signing is done via the keys from the `authentication` verification relationship in the DID Doc
        for the DID to be used for signing
        - if 'sign_frm' is a DID, then the first sender's `authentication` verification method is used for which
        a private key in the secrets resolver is found
        - if 'sign_frm' is a key ID, then the sender's `authentication` verification method identified by the given key ID is used.

    :raises InvalidArgument: if invalid input is provided.
    For example, if `frm` argument doesn't match `from` header in Plaintext,
    or `to` argument doesn't match any of `to` header values in Plaintext.
    :raises UnknownSenderException: if the sender DID or keyID can not be resolved
    :raises UnknownRecipientException: if the target DID or keyID can not be resolved
    :raises IncompatibleKeysException: if the sender and target keys are not compatible

    :param plaintext: the plaintext message to be packed
    :param frm: a DID or key ID the sender uses for authenticated encryption.
    Must match `from` header in Plaintext if the header is set.
    If authentication is not required by the provided 'pack_config' (auth_mode=AuthMode.NO_AUTH),
    then any value can be passed to 'frm'.
    :param to: a target DID or key ID the plaintext will be encrypted for.
    Must match any of `to` header values in Plaintext if the header is set.
    :param pack_config: configuration defining how pack needs to be done.
    If not specified - default configuration is used.
    :param pack_params: optional parameters for pack
    :return: a pack result consisting of a packed message as a JSON string
    and an optional service endpoint to be used to transport teh packed message.
    """
    return PackResult(packed_msg="", service_endpoint="")
