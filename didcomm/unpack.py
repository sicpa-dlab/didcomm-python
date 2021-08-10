from dataclasses import dataclass
from typing import Optional, List

from didcomm.common.algorithms import AnonCryptAlg, AuthCryptAlg, SignAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JWS, JSON, DID_URL
from didcomm.plaintext import Plaintext


@dataclass(frozen=True)
class UnpackConfig:
    """
    Unpack configuration.

    If unpack config expects a particular property (for example that a message is encrypted)
    and the packed message doesn't meet the criteria (it's not encrypted), then a corresponding
    exception will be raised.

    Attributes:
        expect_encrypted (bool): Whether the plaintext must be encrypted by the sender. Not expected by default.
        expect_authenticated (bool): Whether the plaintext must be authenticated by the sender. Not expected by default.
        expect_anonymous_sender (bool): Whether the sender ID must be protected. Not expected by default.
        expect_non_repudiation (bool): Whether the plaintext must be signed by the sender. Not expected by default.
        expect_signed_by_encrypter (bool): Whether the same DID must be used for encryption and signing. True by default.
        expect_decrypt_by_all_keys (bool): Whether the plaintext must be decryptable by all keys resolved by the secrets resolver. False by default.
        unwrap_re_wrapping_forward (bool): If True (default), and the packed message is a Forward
                                           wrapping a plaintext packed for the given recipient,
                                           then both Forward and packed plaintext are unpacked automatically,
                                           and the unpacked plaintext will be returned instead of unpacked Forward.
    """
    expect_non_repudiation: bool = False
    expect_encrypted: bool = False
    expect_authenticated: bool = False
    expect_anonymous_sender: bool = False
    expect_signed_by_encrypter: bool = True
    expect_decrypt_by_all_keys: bool = False
    unwrap_re_wrapping_forward: bool = True


@dataclass(frozen=True)
class Metadata:
    """
    Metadata with details about the packed messaged. Can be used for MTC (message trust context) analysis.

    Attributes:
        encrypted (bool): whether the plaintext has been encrypted
        authenticated (bool): whether the plaintext has been authenticated
        non_repudiation (bool): whether the plaintext has been signed
        anonymous_sender (bool): whether the sender ID was protected
        re_wrapped_in_forward (bool): whether the plaintext was re-wrapped in a forward message by a mediator
        encrypted_from (DID_URL): key ID of the sender used for authentication encryption if the plaintext has been authenticated and encrypted
        encrypted_to (List[DID_URL]): target key IDS for encryption if the plaintext has been encrypted
        sign_from (DID_URL): key ID used for signature if the plaintext has been signed
        enc_alg_auth (AuthCryptAlg): algorithm used for authentication encryption if the plaintext has been authenticated and encrypted
        enc_alg_anon (AnonCryptAlg): algorithm used for anonymous encryption if the plaintext has been encrypted but not authenticated
        sign_alg (SignAlg): signature algorithm in case of non-repudiation
        signed_plaintext (JWS): if the plaintext has been signed, the JWS is returned for non-repudiation purposes
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
    signed_plaintext: Optional[JWS] = None


@dataclass(frozen=True)
class UnpackResult:
    """
    Result of unpack operation.

    Attributes:
        plaintext (Plaintext): unpacked plaintext consisting of headers and application/protocol specific data (body)
        metadata (Metadata): metadata with details about the packed messaged. Can be used for MTC (message trust context) analysis.
    """
    plaintext: Plaintext
    metadata: Metadata


async def unpack(packed_msg: JSON,
                 unpack_config: Optional[UnpackConfig] = None,
                 resolvers_config: Optional[ResolversConfig] = None) -> UnpackResult:
    """
    Unpacks the packed message by doing decryption and verifying the signatures.

    If unpack config expects the message to be packed in a particular way (for example that a message is encrypted)
    and the packed message doesn't meet the criteria (it's not encrypted), then `UnexpectedPackError` will be raised.

    :param packed_msg: the message as JSON string to be unpacked
    :param unpack_config: configuration for unpack. Default parameters are used if not specified.
    :param resolvers_config: Optional resolvers that can override a default resolvers registered by
                             'register_default_secrets_resolver' and 'register_default_did_resolver'

    :raises DIDNotResolvedError: If a DID or DID URL (key ID) can not be resolved or not found
    :raises SecretNotResolvedError: If there is no secret for the given DID or DID URL (key ID)
    :raises MalformedMessageError: if the message is invalid (can not be decrypted, signature is invalid, the plaintext is invalid, etc.)
    :raises UnexpectedPackError: if UnpackOpts expect the message to be packed in a particular way (for example encrypted and signed),
                                   but the message is not

    :return: the plaintext, metadata, and optionally a JWS if the plaintext has been signed.
    """
    return UnpackResult(
        plaintext=Plaintext(body={}, id="", type=""),
        metadata=Metadata(encrypted=True, authenticated=True, non_repudiation=False, anonymous_sender=False)
    )
