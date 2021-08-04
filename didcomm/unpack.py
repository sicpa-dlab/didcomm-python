from dataclasses import dataclass
from typing import Optional, List

from didcomm.common.types import JWS, JSON, DID_OR_DID_URL
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.plaintext import Plaintext
from didcomm.secrets.secrets_resolver import SecretsResolver


@dataclass(frozen=True)
class UnpackConfig:
    secrets_resolver: SecretsResolver = None
    did_resolver: DIDResolver = None
    expect_non_repudiation: bool = False
    expect_encrypted: bool = False
    expect_authenticated: bool = False
    expect_anonymous_sender: bool = False
    expect_signed_by_encrypter: bool = True
    expect_decrypt_by_all_keys: bool = False
    unwrap_re_wrapping_forward: bool = True


@dataclass(frozen=True)
class Metadata:
    encrypted: bool = False
    authenticated: bool = False
    non_repudiation: bool = False
    anonymous_sender: bool = False
    wrapped_in_forward: bool = False
    enc_from: Optional[DID_OR_DID_URL] = None
    enc_to: Optional[List[DID_OR_DID_URL]] = None
    sign_from: Optional[DID_OR_DID_URL] = None


@dataclass(frozen=True)
class UnpackResult:
    plaintext: Plaintext
    metadata: Metadata
    signed_plaintext: Optional[JWS] = None


async def unpack(packed_msg: JSON, unpack_config: Optional[UnpackConfig] = None) -> UnpackResult:
    """
    Unpacks the packed message by doing decryption and verifying the signatures.

    If unpack option expects a particular property (for example that a message is encrypted)
    and the packed message doesn't meet the criteria (for example it's not encrypted), then a corresponding
    exception will be raised.

    If 'unwrap_re_wrapping_forward' is set to True (which is default) in unpack options,
    and the message is a Forward wrapping a plaintext packed for the given recipient,
    then unpacked plaintext will be returned instead of unpacked Forward.

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
    :return: the plaintext, metadata, and optionally a JWS if the plaintext has been signed.
    """
    return UnpackResult(
        plaintext=Plaintext(body={}, id="", type=""),
        metadata=Metadata(),
        signed_plaintext=None
    )
