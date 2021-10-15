from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Union

from authlib.common.encoding import to_unicode, to_bytes

from didcomm.common.algorithms import AnonCryptAlg, AuthCryptAlg, SignAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JWS, JSON, JSON_OBJ, DID_URL
from didcomm.core.anoncrypt import unpack_anoncrypt, is_anoncrypted
from didcomm.core.authcrypt import is_authcrypted, unpack_authcrypt
from didcomm.core.serialization import (
    json_bytes_to_dict,
    json_str_to_dict,
    dict_to_json_bytes,
)
from didcomm.core.sign import is_signed, unpack_sign
from didcomm.errors import DIDCommValueError
from didcomm.core.from_prior import unpack_from_prior_in_place
from didcomm.message import Message
from didcomm.protocols.routing.forward import is_forward, ForwardMessage


async def unpack(
    resolvers_config: ResolversConfig,
    packed_msg: Union[JSON, JSON_OBJ],
    unpack_config: Optional[UnpackConfig] = None,
) -> UnpackResult:
    """
    Unpacks the packed DIDComm message by doing decryption and verifying the signatures.

    :param resolvers_config: secrets and DIDDoc resolvers
    :param packed_msg: packed DIDComm message as JSON string of JSON_OBJ to be unpacked
    :param unpack_config: configuration for unpack. Default parameters are used if not specified.

    :raises DIDDocNotResolvedError: If a DID can not be resolved to a DID Doc.
    :raises DIDUrlNotFoundError: If a DID URL (for example a key ID) is not found within a DID Doc
    :raises SecretNotFoundError: If there is no secret for the given DID or DID URL (key ID)
    :raises MalformedMessageError: if the message is invalid (can not be decrypted, signature is invalid, the message is invalid, etc.)

    :return: the message, metadata, and optionally a JWS if the message has been signed.
    """
    unpack_config = unpack_config or UnpackConfig()

    if isinstance(packed_msg, str):
        msg = to_bytes(packed_msg)
        msg_as_dict = json_str_to_dict(packed_msg)
    elif isinstance(packed_msg, dict):
        msg = dict_to_json_bytes(packed_msg)
        msg_as_dict = packed_msg
    else:
        # FIXME in python it should be a kind of TypeError instead
        raise DIDCommValueError(
            f"unexpected type of packed_message: '{type(packed_msg)}'"
        )

    metadata = Metadata(
        encrypted=False,
        authenticated=False,
        non_repudiation=False,
        anonymous_sender=False,
    )

    if is_anoncrypted(msg_as_dict):
        unwrap_anoncrypt_result = await unpack_anoncrypt(
            msg_as_dict,
            resolvers_config,
            decrypt_by_all_keys=unpack_config.expect_decrypt_by_all_keys,
        )
        msg = unwrap_anoncrypt_result.msg
        msg_as_dict = json_bytes_to_dict(msg)

        metadata.encrypted = True
        metadata.anonymous_sender = True
        metadata.encrypted_to = unwrap_anoncrypt_result.to_kids
        metadata.enc_alg_anon = unwrap_anoncrypt_result.alg

        if is_forward(msg_as_dict) and unpack_config.unwrap_re_wrapping_forward:
            fwd_msg = ForwardMessage.from_json(msg)
            msg_as_dict = fwd_msg.forwarded_msg
            msg = dict_to_json_bytes(msg_as_dict)
            metadata.re_wrapped_in_forward = True

    if is_authcrypted(msg_as_dict):
        unwrap_authcrypt_result = await unpack_authcrypt(
            msg_as_dict,
            resolvers_config,
            decrypt_by_all_keys=unpack_config.expect_decrypt_by_all_keys,
        )
        msg = unwrap_authcrypt_result.msg
        msg_as_dict = json_bytes_to_dict(msg)

        metadata.encrypted = True
        metadata.authenticated = True
        metadata.encrypted_from = unwrap_authcrypt_result.frm_kid
        metadata.encrypted_to = unwrap_authcrypt_result.to_kids
        metadata.enc_alg_auth = unwrap_authcrypt_result.alg

    if is_signed(msg_as_dict):
        unwrap_sign_result = await unpack_sign(msg_as_dict, resolvers_config)
        metadata.signed_message = to_unicode(msg)
        msg = unwrap_sign_result.msg
        msg_as_dict = json_bytes_to_dict(msg)

        metadata.non_repudiation = True
        metadata.authenticated = True
        metadata.sign_from = unwrap_sign_result.sign_frm_kid
        metadata.sign_alg = unwrap_sign_result.alg

    if msg_as_dict.get("from_prior") is not None:
        metadata.from_prior_jwt = msg_as_dict["from_prior"]
    from_prior_issuer_kid = await unpack_from_prior_in_place(
        msg_as_dict, resolvers_config
    )
    metadata.from_prior_issuer_kid = from_prior_issuer_kid

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
        from_prior_issuer_kid: (DID_URL): key ID to sign from_prior if the message contains it
        enc_alg_auth (AuthCryptAlg): algorithm used for authentication encryption if the message has been authenticated and encrypted
        enc_alg_anon (AnonCryptAlg): algorithm used for anonymous encryption if the message has been encrypted but not authenticated
        sign_alg (SignAlg): signature algorithm in case of non-repudiation
        signed_message (JWS): if the message has been signed, the JWS is returned for non-repudiation purposes
        from_prior_jwt (str): if the message contains from_prior field, the JWT (compactly serialized JWS with claim set) containing from_prior
            is returned for non-repudiation purposes
    """

    encrypted: bool
    authenticated: bool
    non_repudiation: bool
    anonymous_sender: bool
    re_wrapped_in_forward: bool = False
    encrypted_from: Optional[DID_URL] = None
    encrypted_to: Optional[List[DID_URL]] = None
    sign_from: Optional[DID_URL] = None
    from_prior_issuer_kid: Optional[DID_URL] = None
    enc_alg_auth: Optional[AuthCryptAlg] = None
    enc_alg_anon: Optional[AnonCryptAlg] = None
    sign_alg: Optional[SignAlg] = None
    signed_message: Optional[JWS] = None
    from_prior_jwt: Optional[str] = None


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
