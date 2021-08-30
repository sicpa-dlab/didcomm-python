from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List

from didcomm.common.algorithms import AuthCryptAlg, AnonCryptAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JSON, DID_OR_DID_URL
from didcomm.message import MessageOptionalHeaders, Message


async def pack_encrypted(
    message: Message,
    to: DID_OR_DID_URL,
    frm: Optional[DID_OR_DID_URL] = None,
    sign_frm: Optional[DID_OR_DID_URL] = None,
    pack_config: Optional[PackEncryptedConfig] = None,
    pack_params: Optional[PackEncryptedParameters] = None,
    resolvers_config: Optional[ResolversConfig] = None,
) -> PackEncryptedResult:
    """
    Produces `DIDComm Encrypted Message`
    https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-message.

    The method encrypts and optionally authenticates the message to the given recipient.

    A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) that
      - hides its content from all but authorized recipients
      - (optionally) discloses and proves the sender to only those recipients
      - provides message integrity guarantees

    It is important in privacy-preserving routing. It is what normally moves over network transports in DIDComm
    applications, and is the safest format for storing DIDComm data at rest.

    Pack is done according to the given Pack Config.
    The default config performs repudiable encryption (auth_crypt if `frm` is set and anon_crypt otherwise)
    and prepares a message for forwarding to the returned endpoint (via Forward protocol).

    It's possible to add non-repudiation by providing `sign_frm` argument (DID or key ID). Signed messages are only necessary when
        - the origin of plaintext must be provable to third parties
        - or the sender can’t be proven to the recipient by authenticated encryption because the recipient
          is not known in advance (e.g., in a broadcast scenario).

    Adding a signature when one is not needed can degrade rather than enhance security because it
    relinquishes the sender’s ability to speak off the record.

    Encryption is done as follows:
        - encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
        - if `frm` is None, then anonymous encryption is done (anoncrypt).
          Otherwise authenticated encryption is done (authcrypt).
        - if `frm` is a DID, then the first sender's `keyAgreement` verification method is used which can be resolved
          via _secrets resolver and has the same type as any of recipient keys
        - if `frm` is a key ID, then the sender's `keyAgreement` verification method identified by the given key ID is used.
        - if `to` frm a DID, then multiplex encryption is done for all keys from the receiver's `keyAgreement`
          verification relationship which have the same type as the sender's key
        - if `to` is a key ID, then encryption is done for the receiver's `keyAgreement` verification method identified by the given key ID.

    If non-repudiation (signing) is added by specifying a `sign_frm` argument:
        - Signing is done via the keys from the `authentication` verification relationship in the DID Doc
          for the DID to be used for signing
        - If `sign_frm` is a DID, then the first sender's `authentication` verification method is used for which
          a private key in the _secrets resolver is found
        - If `sign_frm` is a key ID, then the sender's `authentication` verification method identified by the given key ID is used.

    :param message: The message to be packed into a DIDComm message
    :param to: A target DID or key ID the message will be encrypted for.
               Must match any of `to` header values in Message if the header is set.
    :param frm: A DID or key ID the sender uses for authenticated encryption.
                Must match `from` header in Message if the header is set.
                If not provided - then anonymous encryption is performed.
    :param sign_frm: An optional DID or key ID the sender uses for signing.
                     If not provided - then the message will be repudiable and no signature will be added.
    :param pack_config: Configuration defining how pack needs to be done.
                        If not specified - default configuration is used.
    :param pack_params: Optional parameters for pack
    :param resolvers_config: Optional resolvers that can override a default resolvers registered by
                             `register_default_secrets_resolver` and `register_default_did_resolver`

    :raises ValueError: If invalid input is provided. For example, if `frm` argument doesn't match `from` header in Message,
                        or `to` argument doesn't match any of `to` header values in Message.
    :raises DIDDocNotResolvedError: If a DID can not be resolved to a DID Doc.
    :raises DIDUrlNotFoundError: If a DID URL (for example a key ID) is not found within a DID Doc
    :raises SecretNotFoundError: If there is no secret for the given DID or DID URL (key ID)
    :raises IncompatibleCryptoError: If the sender and target crypto is not compatible
                                     (for example, there are no compatible keys for key agreement)

    :return: A pack result consisting of a packed message as a JSON string
             and an optional service metadata with an endpoint to be used to transport the packed message.
    """
    return PackEncryptedResult(
        packed_msg="",
        service_metadata=ServiceMetadata("", ""),
        from_kid="",
        sign_from_kid="",
        to_kids=[],
    )


@dataclass(frozen=True)
class PackEncryptedResult:
    """
    Result of pack operation.

    Attributes:
        packed_msg (str): A packed message as a JSON string ready to be forwarded to the returned 'service_endpoint'
        service_metadata (ServiceMetadata): An optional service metadata which contains a service endpoint
                                            to be used to transport the 'packed_msg'.
        to_kid (DID_OR_DID_URL): Identifiers (DID URLs) of recipient keys used for message encryption.
        from_kid (DID_OR_DID_URL): Identifier (DID URL) of sender key used for message encryption.
                                   None if anonymous (non-authenticated) encryption is used.
        sign_from_kid (DID_OR_DID_URL): Identifier (DID URL) of sender key used for message signing.
                                        None if there is no signature.
    """

    packed_msg: JSON
    service_metadata: Optional[ServiceMetadata]
    to_kids: List[DID_OR_DID_URL]
    from_kid: Optional[DID_OR_DID_URL]
    sign_from_kid: Optional[DID_OR_DID_URL]


@dataclass(frozen=True)
class ServiceMetadata:
    id: str
    service_endpoint: str


@dataclass(frozen=True)
class PackEncryptedConfig:
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
class PackEncryptedParameters:
    """
    Optional parameters for pack.

    Attributes:
        forward_headers (MessageOptionalHeaders): If forward is enabled (true by default),
                                                  optional headers can be passed to the wrapping Forward messages.
        forward_service_id (str): If forward is enabled (true by default),
                                  optional service ID from recipient's DID Doc to be used for Forwarding.

    """

    forward_headers: Optional[MessageOptionalHeaders] = None
    forward_service_id: Optional[str] = None
