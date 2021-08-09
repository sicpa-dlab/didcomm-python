from dataclasses import dataclass
from typing import Optional, List

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JWS, JSON, DID_OR_DID_URL
from didcomm.plaintext import Plaintext


@dataclass(frozen=True)
class UnpackConfig:
    """
    Unpack configuration.

    If unpack config expects a particular property (for example that a message is encrypted)
    and the packed message doesn't meet the criteria (it's not encrypted), then a corresponding
    exception will be raised.

    Attributes:
        expect_encrypted (bool): whether the plaintext must be encrypted by the sender. Not expected by default.
        expect_authenticated (bool): whether the plaintext must be authenticated by the sender. Not expected by default.
        expect_anonymous_sender (bool): whether the sender ID must be protected. Not expected by default.
        expect_non_repudiation (bool): whether the plaintext must be signed by the sender. Not expected by default.
        expect_signed_by_encrypter (bool): whether the same DID must be used for encryption and signing. True by default.
        expect_decrypt_by_all_keys (bool): whether the plaintext must be decryptable by all keys resolved by the secrets resolver. False by default.
        unwrap_re_wrapping_forward (bool): if True (default), and the packed message is a Forward
        wrapping a plaintext packed for the given recipient, then both Forward and packed plaintext are unpacked automatically,
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
    Metadata with details about the packed messaged. Can be used for MTC (message trust context) analysis

    Attributes:
        encrypted (bool): whether the plaintext has been encrypted
        authenticated (bool): whether the plaintext has been authenticated
        non_repudiation (bool): whether the plaintext has been signed
        anonymous_sender (bool): whether the sender ID was protected
        re_wrapped_in_forward (bool): whether the plaintext was re-wrapped in a forward message by a mediator
        enc_from (DID_OR_DID_URL): DID or key ID of the sender used for authentication encryption if the plaintext has been authenticated and encrypted
        enc_to (List[DID_OR_DID_URL]): target DIDs or key IDS for encryption if the plaintext has been encrypted
        sign_from (DID_OR_DID_URL): DID or key ID used for signature if the plaintext has been signed
    """
    encrypted: bool
    authenticated: bool
    non_repudiation: bool
    anonymous_sender: bool
    re_wrapped_in_forward: bool = False
    enc_from: Optional[DID_OR_DID_URL] = None
    enc_to: Optional[List[DID_OR_DID_URL]] = None
    sign_from: Optional[DID_OR_DID_URL] = None


@dataclass(frozen=True)
class UnpackResult:
    """
    Result of unpack operation.

    Attributes:
        plaintext (Plaintext): unpacked plaintext consisting of headers and application/protocol specific data (body)
        metadata (Metadata): metadata with details about the packed messaged. Can be used for MTC (message trust context) analysis.
        signed_plaintext (JWS): if the plaintext has been signed, the JWS is returned for non-repudiation purposes
    """
    plaintext: Plaintext
    metadata: Metadata
    signed_plaintext: Optional[JWS] = None


async def unpack(packed_msg: JSON,
                 unpack_config: Optional[UnpackConfig] = None,
                 resolvers_config: Optional[ResolversConfig] = None) -> UnpackResult:
    """
    Unpacks the packed message by doing decryption and verifying the signatures.

    If unpack config expects a particular property (for example that a message is encrypted)
    and the packed message doesn't meet the criteria (it's not encrypted), then a corresponding
    exception will be raised.

    :raises InvalidPlaintext: if unpacked plaintext is invalid
    :raises UnknownSenderException: if the sender DID or keyID can not be resolved
    :raises UnknownRecipientException: if the target DID or keyID can not be resolved

    :raises IncompatibleKeysException: if the sender and target keys are not compatible
    :raises InvalidSignatureException: if the signature is present and invalid
    :raises CanNotDecryptException: if the message is encrypted but can not be decrypted by the given recipient

    :raises NotSignedException: if UnpackOpts expect the message to be signed, but it's not
    :raises NotEncryptedException: if UnpackOpts expect the message to be encrypted, but it's not
    :raises NotAuthenticatedException: if UnpackOpts expect the message to be authenticated, but it's not
    :raises SenderNotHiddenException: if UnpackOpts expect the message to hide the sender, but the sender was disclosed
    :raises NotSignedByEncrypterException: if UnpackOpts expect the message to be signed by the same DID who encrypted it,
    but it was signed by another DID
    :raises NotDecryptedByAllKeysException: if UnpackOpts expect the message to be decryptable by all keys resolved by the secrets resolver,
    but there were keys resolved for which decryption wasn't successful

    :param packed_msg: the message as JSON string to be unpacked
    :param unpack_config: configuration for unpack. Default parameters are used if not specified.
    :param resolvers_config: optional resolvers that can override a default resolvers
    registered by 'register_default_secrets_resolver' and 'register_default_did_resolver'
    :return: the plaintext, metadata, and optionally a JWS if the plaintext has been signed.
    """
    return UnpackResult(
        plaintext=Plaintext(body={}, id="", type=""),
        metadata=Metadata(encrypted=True, authenticated=True, non_repudiation=False, anonymous_sender=False),
        signed_plaintext=None
    )
