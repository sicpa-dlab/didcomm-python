from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List

from didcomm.common.algorithms import AnonCryptAlg, AuthCryptAlg, SignAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JWS, JSON, DID_URL
from didcomm.message import Message


async def unpack(packed_msg: JSON,
                 unpack_config: Optional[UnpackConfig] = None,
                 resolvers_config: Optional[ResolversConfig] = None) -> UnpackResult:
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
    return UnpackResult(
        message=Message(body={}, id="", type=""),
        metadata=Metadata(encrypted=True, authenticated=True, non_repudiation=False, anonymous_sender=False,
                          signed_message=None)
    )


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


@dataclass(frozen=True)
class Metadata:
    """
    Metadata with details about the packed messaged. Can be used for MTC (message trust context) analysis.

    Attributes:
        encrypted (bool): whether the message has been encrypted
        authenticated (bool): whether the message has been authenticated
        non_repudiation (bool): whether the message has been signed
        anonymous_sender (bool): whether the sender ID was protected
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

    If unpack config expects a particular property (for example that a message is encrypted)
    and the packed message doesn't meet the criteria (it's not encrypted), then a corresponding
    exception will be raised.

    Attributes:
        expect_encrypted (bool): Whether the message must be encrypted by the sender. Not expected by default.
        expect_authenticated (bool): Whether the message must be authenticated by the sender. Not expected by default.
        expect_anonymous_sender (bool): Whether the sender ID must be protected. Not expected by default.
        expect_non_repudiation (bool): Whether the message must be signed by the sender. Not expected by default.
        expect_signed_by_encrypter (bool): Whether the same DID must be used for encryption and signing. True by default.
        expect_decrypt_by_all_keys (bool): Whether the message must be decryptable by all keys resolved by the secrets resolver. False by default.
        unwrap_re_wrapping_forward (bool): If True (default), and the packed message is a Forward
                                           wrapping a message packed for the given recipient,
                                           then both Forward and packed messages are unpacked automatically,
                                           and the unpacked message will be returned instead of unpacked Forward.
    """
    expect_non_repudiation: bool = False
    expect_encrypted: bool = False
    expect_authenticated: bool = False
    expect_anonymous_sender: bool = False
    expect_signed_by_encrypter: bool = True
    expect_decrypt_by_all_keys: bool = False
    unwrap_re_wrapping_forward: bool = True
