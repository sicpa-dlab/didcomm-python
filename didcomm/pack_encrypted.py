from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List

from didcomm.common.algorithms import AuthCryptAlg, AnonCryptAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JSON, DID_OR_DID_URL
from didcomm.core.anoncrypt import anoncrypt, find_keys_and_anoncrypt
from didcomm.core.authcrypt import find_keys_and_authcrypt
from didcomm.core.serialization import dict_to_json
from didcomm.core.sign import sign
from didcomm.core.types import EncryptResult, SignResult
from didcomm.core.utils import get_did, is_did
from didcomm.errors import DIDCommValueError
from didcomm.message import Message, Header


async def pack_encrypted(
    resolvers_config: ResolversConfig,
    message: Message,
    to: DID_OR_DID_URL,
    frm: Optional[DID_OR_DID_URL] = None,
    sign_frm: Optional[DID_OR_DID_URL] = None,
    pack_config: Optional[PackEncryptedConfig] = None,
    pack_params: Optional[PackEncryptedParameters] = None,
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

    :param resolvers_config: secrets and DIDDoc resolvers
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

    :raises DIDCommValueError: If invalid input is provided. For example, if `frm` argument doesn't match `from` header in Message,
                               or `to` argument doesn't match any of `to` header values in Message.
    :raises DIDDocNotResolvedError: If a DID can not be resolved to a DID Doc.
    :raises DIDUrlNotFoundError: If a DID URL (for example a key ID) is not found within a DID Doc
    :raises SecretNotFoundError: If there is no secret for the given DID or DID URL (key ID)
    :raises IncompatibleCryptoError: If the sender and target crypto is not compatible
                                     (for example, there are no compatible keys for key agreement)

    :return: A pack result consisting of a packed message as a JSON string
             and an optional service metadata with an endpoint to be used to transport the packed message.
    :rtype: PackEncryptedResult
    """

    pack_config = pack_config or PackEncryptedConfig()
    pack_params = pack_params or PackEncryptedParameters()

    # 1. validate message
    __validate(message, to, frm, sign_frm)

    # 2. message as dict
    msg_as_dict = message.as_dict()

    # 3. sign if needed
    sign_res = await __sign_if_needed(resolvers_config, msg_as_dict, sign_frm)

    # 4. encrypt
    encrypt_res = await __encrypt(
        resolvers_config,
        msg=sign_res.msg if sign_res else msg_as_dict,
        to=to,
        frm=frm,
        pack_config=pack_config,
    )

    # 5. protected sender ID if needed
    encrypt_res_protected = __protected_sender_id_if_needed(encrypt_res, pack_config)

    # 6. do forward if needed
    await __forward_if_needed()  # TBD

    packed_msg = dict_to_json(
        encrypt_res_protected.msg if encrypt_res_protected else encrypt_res.msg
    )
    return PackEncryptedResult(
        packed_msg=packed_msg,
        service_metadata=ServiceMetadata("", ""),
        to_kids=encrypt_res.to_kids,
        from_kid=encrypt_res.from_kid,
        sign_from_kid=sign_res.sign_frm_kid if sign_res else None,
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


@dataclass
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


@dataclass
class PackEncryptedParameters:
    """
    Optional parameters for pack.

    Attributes:
        forward_headers (MessageOptionalHeaders): If forward is enabled (true by default),
                                                  optional headers can be passed to the wrapping Forward messages.
        forward_service_id (str): If forward is enabled (true by default),
                                  optional service ID from recipient's DID Doc to be used for Forwarding.

    """

    forward_headers: Optional[List[Header]] = None
    forward_service_id: Optional[str] = None


def __validate(
    message: Message,
    to: DID_OR_DID_URL,
    frm: Optional[DID_OR_DID_URL] = None,
    sign_frm: Optional[DID_OR_DID_URL] = None,
):
    if not is_did(to):
        raise DIDCommValueError()

    if frm is not None and not is_did(frm):
        raise DIDCommValueError()

    if sign_frm is not None and not is_did(sign_frm):
        raise DIDCommValueError()

    if message.to is not None and get_did(to) not in message.to:
        raise DIDCommValueError()

    if frm is not None and message.frm is not None and get_did(frm) != message.frm:
        raise DIDCommValueError()


async def __sign_if_needed(
    resolvers_config: ResolversConfig,
    msg: dict,
    sign_frm: Optional[DID_OR_DID_URL] = None,
) -> Optional[SignResult]:
    if sign_frm is None:
        return None
    return await sign(msg, sign_frm, resolvers_config)


async def __encrypt(
    resolvers_config: ResolversConfig,
    msg: dict,
    to: DID_OR_DID_URL,
    frm: Optional[DID_OR_DID_URL] = None,
    pack_config: Optional[PackEncryptedConfig] = None,
) -> EncryptResult:
    if frm is not None:
        return await find_keys_and_authcrypt(
            msg, to, frm, pack_config.enc_alg_auth, resolvers_config
        )
    return await find_keys_and_anoncrypt(
        msg, to, pack_config.enc_alg_anon, resolvers_config
    )


def __protected_sender_id_if_needed(
    encrypt_result: EncryptResult, pack_config: Optional[PackEncryptedConfig] = None
) -> Optional[EncryptResult]:
    if encrypt_result.from_kid is None or not pack_config.protect_sender_id:
        return None
    return anoncrypt(
        encrypt_result.msg, encrypt_result.to_keys, pack_config.enc_alg_anon
    )


async def __forward_if_needed():
    # TBD
    pass
