from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from didcomm.common.algorithms import AuthCryptAlg, AnonCryptAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JSON, DID_OR_DID_URL, ServiceMetadata
from didcomm.plaintext import Plaintext, PlaintextOptionalHeaders


@dataclass(frozen=True)
class PackResult:
    """
    Result of pack operation.

    Attributes:
        packed_msg (str): A packed message as a JSON string ready to be forwarded to the returned 'service_endpoint'
        service_metadata (ServiceMetadata): An optional service metadata which contains a service endpoint
                                            to be used to transport the 'packed_msg'.
    """
    packed_msg: JSON
    service_metadata: Optional[ServiceMetadata]


@dataclass(frozen=True)
class PackConfig:
    """
    Pack configuration.

    Default config performs repudiable authentication encryption (auth_crypt)
    and prepares a message ready to be forwarded to the returned endpoint (via Forward protocol).

    Attributes:
        enc_alg_auth (AuthCryptAlg): The encryption algorithm to be used for authentication encryption (auth_crypt).
                                     `A256CBC_HS512_ECDH_1PU_A256KW` by default.
        enc_alg_anon (AnonCryptAlg): The encryption algorithm to be used for anonymous encryption (anon_crypt).
                                     `XC20P_ECDH_ES_A256KW` by default.
        protect_sender_id (bool): Whether the sender's identity needs to be protected during authentication encryption.
        forward (bool): Whether the packed messages need to be wrapped into Forward messages to be sent to Mediators
                        as defined by the Forward protocol. True by default.
    """
    enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW
    enc_alg_anon: AnonCryptAlg = AnonCryptAlg.XC20P_ECDH_ES_A256KW
    protect_sender_id: bool = False
    forward: bool = True


@dataclass(frozen=True)
class PackParameters:
    """
    Optional parameters for pack.

    Attributes:
        forward_headers (PlaintextOptionalHeaders): If forward is enabled (true by default),
                                                    optional headers can be passed to the wrapping Forward messages.
        forward_service_id (str): If forward is enabled (true by default),
                                  optional service ID from recipient's DID Doc to be used for Forwarding.

    """
    forward_headers: Optional[PlaintextOptionalHeaders] = None
    forward_service_id: Optional[str] = None


async def pack_encrypted(plaintext: Plaintext,
                         to: DID_OR_DID_URL,
                         frm: Optional[DID_OR_DID_URL] = None,
                         sign_frm: Optional[DID_OR_DID_URL] = None,
                         pack_config: Optional[PackConfig] = None,
                         pack_params: Optional[PackParameters] = None,
                         resolvers_config: Optional[ResolversConfig] = None) -> PackResult:
    """
    Packs (encrypts and optionally authenticates) the message to the given recipient.

    Pack is done according to the given Pack Config.
    Default config performs repudiable encryption (auth_crypt if `frm` is set and anon_crypt otherwise)
    and prepares a message ready to be forwarded to the returned endpoint (via Forward protocol).

    It's possible to add non-repudiation by providing `sign_frm` argument (DID or key ID).
    Signed messages are only necessary when the origin of plaintext must be provable
    to third parties, or when the sender can’t be proven to the recipient by authenticated encryption because
    the recipient is not known in advance (e.g., in a broadcast scenario).
    Adding a signature when one is not needed can degrade rather than enhance security because
    it relinquishes the sender’s ability to speak off the record.

    Encryption is done as following:
        - encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
        - if `frm` is None, then anonymous encryption is done (anoncrypt).
          Otherwise authenticated encryption is done (authcrypt).
        - if `frm` is a DID, then the first sender's `keyAgreement` verification method is used which can be resolved
          via secrets resolver and has the same type as any of recipient keys
        - if `frm` is a key ID, then the sender's `keyAgreement` verification method identified by the given key ID is used.
        - if `to` frm a DID, then multiplex encryption is done for all keys from the receiver's `keyAgreement`
          verification relationship which have the same type as the sender's key
        - if `to` is a key ID, then encryption is done for the receiver's `keyAgreement` verification method identified by the given key ID.

    If non-repudiation (signing) is added by specifying a `sign_frm` argument:
        - Signing is done via the keys from the `authentication` verification relationship in the DID Doc
          for the DID to be used for signing
        - If `sign_frm` is a DID, then the first sender's `authentication` verification method is used for which
          a private key in the secrets resolver is found
        - If `sign_frm` is a key ID, then the sender's `authentication` verification method identified by the given key ID is used.

    :param plaintext: The plaintext to be packed
    :param to: A target DID or key ID the plaintext will be encrypted for.
               Must match any of `to` header values in Plaintext if the header is set.
    :param frm: A DID or key ID the sender uses for authenticated encryption.
                Must match `from` header in Plaintext if the header is set.
                If not provided - then anonymous encryption is performed.
    :param sign_frm: An optional DID or key ID the sender uses for signing.
                     If not provided - then the message will be repudiable and no signature will be added.
    :param pack_config: Configuration defining how pack needs to be done.
                        If not specified - default configuration is used.
    :param pack_params: Optional parameters for pack
    :param resolvers_config: Optional resolvers that can override a default resolvers registered by
                             `register_default_secrets_resolver` and `register_default_did_resolver`

    :raises ValueError: If invalid input is provided. For example, if `frm` argument doesn't match `from` header in Plaintext,
                        or `to` argument doesn't match any of `to` header values in Plaintext.
    :raises DIDNotResolvedError: If a DID or DID URL (key ID) can not be resolved or not found
    :raises SecretNotResolvedError: If there is no secret for the given DID or DID URL (key ID)
    :raises IncompatibleKeysException: If the sender and target keys are not compatible

    :return: A pack result consisting of a packed message as a JSON string
             and an optional service metadata with an endpoint to be used to transport the packed message.
    """
    return PackResult(packed_msg="", service_metadata=ServiceMetadata("", ""))


async def pack_signed(plaintext: Plaintext,
                      sign_frm: DID_OR_DID_URL,
                      resolvers_config: Optional[ResolversConfig] = None) -> JSON:
    """
    Packs a signed (non-repudiation added) but unencrypted message that can be publicly published.

    Signed messages are only necessary when the origin of plaintext must be provable
    to third parties, or when the sender can’t be proven to the recipient by authenticated encryption because
    the recipient is not known in advance (e.g., in a broadcast scenario).
    Adding a signature when one is not needed can degrade rather than enhance security because
    it relinquishes the sender’s ability to speak off the record.

    Signing is done as following:
        - Signing is done via the keys from the `authentication` verification relationship in the DID Doc
          for the DID to be used for signing
        - If `sign_frm` is a DID, then the first sender's `authentication` verification method is used for which
          a private key in the secrets resolver is found
        - If `sign_frm` is a key ID, then the sender's `authentication` verification method identified by the given key ID is used.

    :param plaintext: The plaintext to be packed
    :param sign_frm: DID or key ID the sender uses for signing.
    :param resolvers_config: Optional resolvers that can override a default resolvers registered by
                             `register_default_secrets_resolver` and `register_default_did_resolver`

    :raises DIDNotResolvedError: If a DID or DID URL (key ID) can not be resolved or not found
    :raises SecretNotResolvedError: If there is no secret for the given DID or DID URL (key ID)

    :return: A packed message as a JSON string.
    """
    return ""


async def pack_plaintext(plaintext: Plaintext, resolvers_config: Optional[ResolversConfig] = None) -> JSON:
    """
    Packs the message as a plaintext. The message is not signed and not encrypted.

    :param plaintext: The plaintext to be packed
    :param resolvers_config: Optional resolvers that can override a default resolvers registered by
                             `register_default_secrets_resolver` and `register_default_did_resolver`

    :raises DIDNotResolvedError: If a DID or DID URL (key ID) can not be resolved or not found
    :raises SecretNotResolvedError: If there is no secret for the given DID or DID URL (key ID)

    :return: A packed message as a JSON string.
    """
    return ""
