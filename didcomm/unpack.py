from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List

from authlib.common.encoding import json_loads, to_unicode, to_bytes

from didcomm.common.algorithms import AnonCryptAlg, AuthCryptAlg, SignAlg
from didcomm.common.resolvers import ResolversConfig, get_effective_resolvers
from didcomm.common.types import JWS, JSON, DID_URL
from didcomm.common.utils import parse_base64url_encoded_json
from didcomm.core.anoncrypt import unwrap_anoncrypt
from didcomm.core.authcrypt import unwrap_authcrypt
from didcomm.core.sign import unwrap_sign
from didcomm.message import Message


async def unpack(
    packed_msg: JSON,
    unpack_config: Optional[UnpackConfig] = None,
    resolvers_config: Optional[ResolversConfig] = None,
) -> UnpackResult:
    """
    Unpacks the packed DIDComm message by doing decryption and verifying the signatures.

    If unpack config expects the message to be packed in a particular way (for example that a message is encrypted)
    and the packed message doesn't meet the criteria (it's not encrypted), then `UnsatisfiedConstraintError` will be raised.

    :param packed_msg: packed DIDComm message as JSON string to be unpacked
    :param unpack_config: configuration for unpack. Default parameters are used if not specified.
    :param resolvers_config: Optional resolvers that can override a default resolvers registered by
                             `register_default_secrets_resolver` and `register_default_did_resolver`

    :raises DIDDocNotResolvedError: If a DID can not be resolved to a DID Doc.
    :raises DIDUrlNotFoundError: If a DID URL (for example a key ID) is not found within a DID Doc
    :raises SecretNotFoundError: If there is no secret for the given DID or DID URL (key ID)
    :raises MalformedMessageError: if the message is invalid (can not be decrypted, signature is invalid, the message is invalid, etc.)
    :raises UnsatisfiedConstraintError: if UnpackOpts expect the message to be packed in a particular way (for example encrypted and signed),
                                        but the message is not

    :return: the message, metadata, and optionally a JWS if the message has been signed.
    """
    resolvers_config = get_effective_resolvers(resolvers_config)

    msg = to_bytes(packed_msg)
    msg_as_dict = json_loads(packed_msg)

    metadata = Metadata(
        encrypted=False,
        authenticated=False,
        non_repudiation=False,
        anonymous_sender=False,
    )

    if "ciphertext" in msg_as_dict and parse_base64url_encoded_json(
        msg_as_dict["protected"]
    )["alg"].startswith("ECDH-ES"):

        unwrap_anoncrypt_result = await unwrap_anoncrypt(msg_as_dict, resolvers_config)

        msg = unwrap_anoncrypt_result.msg
        msg_as_dict = json_loads(to_unicode(msg))

        metadata.encrypted = True
        metadata.anonymous_sender = True
        metadata.encrypted_to = unwrap_anoncrypt_result.to_kids
        metadata.enc_alg_anon = unwrap_anoncrypt_result.alg

    if "ciphertext" in msg_as_dict and parse_base64url_encoded_json(
        msg_as_dict["protected"]
    )["alg"].startswith("ECDH-1PU"):

        unwrap_authcrypt_result = await unwrap_authcrypt(msg_as_dict, resolvers_config)

        msg = unwrap_authcrypt_result.msg
        msg_as_dict = json_loads(to_unicode(msg))

        metadata.encrypted = True
        metadata.authenticated = True
        metadata.encrypted_from = unwrap_authcrypt_result.frm_kid
        metadata.encrypted_to = unwrap_authcrypt_result.to_kids
        metadata.enc_alg_auth = unwrap_authcrypt_result.alg

    if "payload" in msg_as_dict:
        unwrap_sign_result = await unwrap_sign(msg_as_dict, resolvers_config)
        metadata.signed_message = to_unicode(msg)

        msg = unwrap_sign_result.msg
        msg_as_dict = json_loads(to_unicode(msg))

        metadata.non_repudiation = True
        metadata.sign_from = unwrap_sign_result.sign_frm_kid
        metadata.sign_alg = unwrap_sign_result.alg

    # TODO: Validate `msg_as_dict` structure
    message = Message.from_dict(msg_as_dict)

    return UnpackResult(message=message, metadata=metadata)


@dataclass(frozen=True)
class UnpackResult:
    """
    Result of unpack operation.

    Attributes:
        message (Message): unpacked message consisting of headers and application/protocol specific data (body)
        metadata (Metadata): metadata with details about the packed messaged. Can be used for MTC (message trust context) analysis.
    """

    message: Message
    metadata: Metadata


@dataclass
class Metadata:
    """
    Metadata with details about the packed messaged. Can be used for MTC (message trust context) analysis.

    Attributes:
        encrypted (bool): whether the message has been encrypted
        authenticated (bool): whether the message has been authenticated by using authcrypt
        non_repudiation (bool): whether the message has been signed
        anonymous_sender (bool): whether the sender ID was hidden or protected
        re_wrapped_in_forward (bool): whether the message was re-wrapped in a forward message by a mediator
        encrypted_from (DID_URL): key ID of the sender used for authentication encryption if the message has been authenticated and encrypted
        encrypted_to (List[DID_URL]): target key IDS for encryption if the message has been encrypted
        sign_from (DID_URL): key ID used for signature if the message has been signed
        enc_alg_auth (AuthCryptAlg): algorithm used for authentication encryption if the message has been authenticated and encrypted
        enc_alg_anon (AnonCryptAlg): algorithm used for anonymous encryption if the message has been encrypted but not authenticated
        sign_alg (SignAlg): signature algorithm in case of non-repudiation
        signed_message (JWS): if the message has been signed, the JWS is returned for non-repudiation purposes
    """

    encrypted: bool
    authenticated: bool
    non_repudiation: bool
    anonymous_sender: bool
    re_wrapped_in_forward: bool = False
    encrypted_from: Optional[DID_URL] = None
    encrypted_to: Optional[List[DID_URL]] = None
    sign_from: Optional[DID_URL] = None
    enc_alg_auth: Optional[AuthCryptAlg] = None
    enc_alg_anon: Optional[AnonCryptAlg] = None
    sign_alg: Optional[SignAlg] = None
    signed_message: Optional[JWS] = None


@dataclass(frozen=True)
class UnpackConfig:
    """
    Unpack configuration.

    If unpack config expects a particular property and the packed message doesn't meet the criteria,
    then a corresponding exception will be raised.

    Attributes:
        expect_decrypt_by_all_keys (bool): Whether the message must be decryptable by all keys resolved by the secrets
                                           resolver. False by default.
        unwrap_re_wrapping_forward (bool): If True (default), and the packed message is a Forward
                                           wrapping a message packed for the given recipient,
                                           then both Forward and packed messages are unpacked automatically,
                                           and the unpacked message will be returned instead of unpacked Forward.
    """

    expect_decrypt_by_all_keys: bool = False
    unwrap_re_wrapping_forward: bool = True
