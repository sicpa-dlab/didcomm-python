from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, List

from didcomm.common.algorithms import AuthCryptAlg, AnonCryptAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JSON, JSON_OBJ, DID_OR_DID_URL, DID_URL
from didcomm.core.anoncrypt import anoncrypt, find_keys_and_anoncrypt
from didcomm.core.authcrypt import find_keys_and_authcrypt
from didcomm.core.defaults import DEF_ENC_ALG_AUTH, DEF_ENC_ALG_ANON
from didcomm.core.serialization import dict_to_json
from didcomm.core.sign import sign
from didcomm.core.types import EncryptResult, SignResult, DIDCommGeneratorType
from didcomm.core.utils import get_did, is_did, didcomm_id_generator_default
from didcomm.did_doc.did_doc import DIDCommService
from didcomm.errors import DIDCommValueError
from didcomm.core.from_prior import pack_from_prior_in_place
from didcomm.message import Message, Header
from didcomm.protocols.routing.forward import (
    wrap_in_forward,
    resolve_did_services_chain,
    ForwardPackResult,
)

logger = logging.getLogger(__name__)


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

    # 3. Pack from_prior in place
    from_prior_issuer_kid = await pack_from_prior_in_place(
        msg_as_dict,
        resolvers_config,
        pack_params.from_prior_issuer_kid,
    )

    # 4. sign if needed
    sign_res = await __sign_if_needed(resolvers_config, msg_as_dict, sign_frm)

    # 5. encrypt
    encrypt_res = await __encrypt(
        resolvers_config,
        msg=sign_res.msg if sign_res else msg_as_dict,
        to=to,
        frm=frm,
        pack_config=pack_config,
    )

    # 6. protected sender ID if needed
    encrypt_res_protected = __protected_sender_id_if_needed(encrypt_res, pack_config)

    packed_msg_dict = (
        encrypt_res_protected.msg if encrypt_res_protected else encrypt_res.msg
    )

    # 7. resolve service information
    did_services_chain = await resolve_did_services_chain(
        resolvers_config, to, pack_params.forward_service_id
    )

    # 8. do forward if needed
    fwd_res = await __forward_if_needed(
        resolvers_config,
        packed_msg_dict,
        to,
        did_services_chain,
        pack_config,
        pack_params,
    )

    packed_msg = dict_to_json(fwd_res.msg_encrypted.msg if fwd_res else packed_msg_dict)

    return PackEncryptedResult(
        packed_msg=packed_msg,
        to_kids=encrypt_res.to_kids,
        from_kid=encrypt_res.from_kid,
        sign_from_kid=sign_res.sign_frm_kid if sign_res else None,
        from_prior_issuer_kid=from_prior_issuer_kid,
        service_metadata=ServiceMetadata(
            did_services_chain[-1].id, did_services_chain[0].service_endpoint
        )
        if did_services_chain
        else None,
    )


@dataclass(frozen=True)
class PackEncryptedResult:
    """
    Result of pack operation.

    Attributes:
        packed_msg (str): A packed message as a JSON string ready to be forwarded to the returned 'service_endpoint'
        service_metadata (ServiceMetadata): An optional service metadata which contains a service endpoint
                                            to be used to transport the 'packed_msg'.
        to_kid (DID_URL): Identifiers (DID URLs) of recipient keys used for message encryption.
        from_kid (DID_URL): Identifier (DID URL) of sender key used for message encryption.
                            None if anonymous (non-authenticated) encryption is used.
        sign_from_kid (DID_URL): Identifier (DID URL) of sender key used for message signing.
                                 None if there is no signature.
        from_prior_issuer_kid (DID_URL): Identifier (DID URL) of issuer key used for signing from_prior.
                                         None if the message does not contain from_prior.
    """

    packed_msg: JSON
    to_kids: List[DID_URL]
    from_kid: Optional[DID_URL]
    sign_from_kid: Optional[DID_URL]
    from_prior_issuer_kid: Optional[DID_URL] = None
    service_metadata: Optional[ServiceMetadata] = None


@dataclass(frozen=True)
class ServiceMetadata:
    """
    Resolved DID DOC Service metadata.

    Attributes:
        id (str): service's 'id' field of the final recipient DID Doc Service
        service_endpoint (str): resolved URI to be used for transport
    """

    id: str
    service_endpoint: str


@dataclass
class PackEncryptedConfig:
    """
    Pack configuration.

    Default config performs repudiable authentication encryption (auth_crypt)
    and prepares a message ready to be forwarded to the returned endpoint
    (via Forward protocol).

    Attributes:
        enc_alg_auth (AuthCryptAlg): The encryption algorithm to be used for
            authentication encryption (auth_crypt).
            `A256CBC_HS512_ECDH_1PU_A256KW` by default.
        enc_alg_anon (AnonCryptAlg): The encryption algorithm to be used for
            anonymous encryption (anon_crypt).
            `XC20P_ECDH_ES_A256KW` by default.
        protect_sender_id (bool): Whether the sender's identity needs to be
            protected during authentication encryption.
        forward (bool): Whether the packed messages need to be wrapped into
            Forward messages to be sent to Mediators as defined by the Forward
            protocol. True by default.
    """

    enc_alg_auth: AuthCryptAlg = DEF_ENC_ALG_AUTH
    enc_alg_anon: AnonCryptAlg = DEF_ENC_ALG_ANON
    protect_sender_id: bool = False
    forward: bool = True


@dataclass
class PackEncryptedParameters:
    """
    Optional parameters for pack.

    Attributes:
        forward_headers (MessageOptionalHeaders): If forward is enabled
            (true by default), optional headers can be passed to the wrapping
            Forward messages.
        forward_service_id (str): If forward is enabled (true by default),
            optional service ID from recipient's DID Doc to be used for
            Forwarding.
        forward_didcomm_id_generator (Callable): optional callable to use
            for forward messages ``id`` generation, ``didcomm_id_generator_default``
            is used by default
        from_prior_issuer_kid (DID_URL): If from_prior is specified in the source message,
            this field can explicitly specify which key to use for signing from_prior
            in the packed message
    """

    forward_headers: Optional[Header] = None
    forward_service_id: Optional[str] = None
    forward_didcomm_id_generator: Optional[
        DIDCommGeneratorType
    ] = didcomm_id_generator_default
    from_prior_issuer_kid: Optional[DID_URL] = None


def __validate(
    message: Message,
    to: DID_OR_DID_URL,
    frm: Optional[DID_OR_DID_URL] = None,
    sign_frm: Optional[DID_OR_DID_URL] = None,
):
    if not is_did(to):
        raise DIDCommValueError(f"`to` value is not a valid DID of DID URL: {to}")

    if frm is not None and not is_did(frm):
        raise DIDCommValueError(f"`from` value is not a valid DID of DID URL: {frm}")

    if sign_frm is not None and not is_did(sign_frm):
        raise DIDCommValueError(
            f"`sign_from` value is not a valid DID of DID URL: {sign_frm}"
        )

    if message.to is not None and not isinstance(message.to, List):
        raise DIDCommValueError(f"`message.to` value is not a list: {message.to}")

    if message.to is not None and get_did(to) not in message.to:
        raise DIDCommValueError(
            f"`message.to` value {message.to} does not contain `to` value's DID {get_did(to)}"
        )

    if frm is not None and message.frm is not None and get_did(frm) != message.frm:
        raise DIDCommValueError(
            f"`message.from` value {message.frm} is not equal to `from` value's DID {get_did(frm)}"
        )


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


async def __forward_if_needed(
    resolvers_config: ResolversConfig,
    packed_msg: JSON_OBJ,
    to: DID_OR_DID_URL,
    did_services_chain: List[DIDCommService],
    pack_config: PackEncryptedConfig,
    pack_params: PackEncryptedParameters,
) -> Optional[ForwardPackResult]:

    if not pack_config.forward:
        logger.debug("forward is turned off")
        return None

    # build routing keys them using recipient service information
    if not did_services_chain:
        logger.debug("No service endpoint found: skipping forward wrapping")
        return None

    # last service is for 'to' DID
    routing_keys = did_services_chain[-1].routing_keys

    if not routing_keys:
        return None

    # prepend routing with alternative endpoints
    # starting from the second mediator if any
    # (the first one considered to have URI endpoint)
    # cases:
    #   ==1 usual sender forward process
    #   >1 alternative endpoints
    #   >2 alternative endpoints recursion
    # TODO
    #   - case: a mediator's service has non-empty routing keys
    #     list (not covered by the spec for now)
    if len(did_services_chain) > 1:
        routing_keys = [
            s.service_endpoint for s in did_services_chain[1:]
        ] + routing_keys

    return await wrap_in_forward(
        resolvers_config=resolvers_config,
        packed_msg=packed_msg,
        to=to,
        routing_keys=routing_keys,
        enc_alg_anon=pack_config.enc_alg_anon,
        headers=pack_params.forward_headers,
        didcomm_id_generator=pack_params.forward_didcomm_id_generator,
    )
