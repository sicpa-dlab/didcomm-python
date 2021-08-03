from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, List

from didcomm.common.types import DID_OR_KID, JWS, JSON
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.plaintext import Plaintext
from didcomm.secrets.secrets_resolver import SecretsResolver


@dataclass(frozen=True)
class UnpackOpts:
    expect_signed: bool = False
    expect_encrypted: bool = False
    expect_authenticated: bool = False
    expect_sender_hidden: bool = False
    expect_signed_by_encrypter: bool = True
    expect_decrypt_by_all_keys: bool = False
    unwrap_re_wrapping_forward: bool = True


class EncType(Enum):
    NO_ENC = auto()
    AUTH = auto()
    ANON = auto()
    ANON_AUTH = auto()


@dataclass(frozen=True)
class Metadata:
    enc_from: Optional[DID_OR_KID] = None
    enc_to: Optional[List[DID_OR_KID]] = None
    enc_typ: EncType = EncType.NO_ENC
    sign_from: Optional[DID_OR_KID] = None


@dataclass(frozen=True)
class UnpackResult:
    plaintext: Plaintext
    metadata: Metadata
    signed_plaintext: Optional[JWS] = None


class Unpacker:
    """
    Unpacks a packed plaintext message.
    Returns the plaintext, metadata, and optionally a JWS if the plaintext has been signed.
    """

    def __init__(self,
                 unpack_opts: UnpackOpts = None,
                 secrets_resolver: SecretsResolver = None,
                 did_resolver: DIDResolver = None):
        """
        A new instance of Unpacker.

        :param unpack_opts: an optional parameters for Unpacker. Default parameters are used if not specified.
        :param secrets_resolver: an optional secrets resolver that can override a default secrets resolver
        registered by 'register_default_secrets_resolver'
        :param did_resolver: an optional DID Doc resolver that can override a default DID Doc resolver
        registered by 'register_default_did_resolver'
        """
        pass

    async def unpack(self, msg: JSON) -> UnpackResult:
        """
        Unpacks the message by doing decryption and verifying the signatures.

        If unpack option expects a particular property (for example that a message is encrypted)
        and the packed message doesn't meet the criteria (for example it's not encrypted), then a corresponding
        exception will be raised.

        If 'unwrap_re_wrapping_forward' is set to True (which is default) in unpack options,
        and the message is a plaintext Forward wrapping a plaintext packed for the given recipient,
        then unpacked plaintext will be returned.

        :raises UnknownSenderException: if the sender DID or keyID can not be resolved
        :raises UnknownRecipientException: if the target DID or keyID can not be resolved

        :raises IncompatibleKeysException: if the sender and target keys are not compatible
        :raises InvalidSignatureException: if the signature is present and invalid
        :raises CanNotDecryptException: if the message is encrypted but can not be decrypted by the given recipient

        :raises NotSignedException: if UnpackOpts expect the message to be signed, but it's not
        :raises NotEncryptedException: if UnpackOpts expect the message to be encrypted, but it's not
        :raises NotAuthenticatedException: if UnpackOpts expect the message to be authenticated, but it's not
        :raises SenderNotHiddenException: if UnpackOpts expect the message to hide the sender, but the sender was disclosed
        :raises NotSignedByEncrypyterException: if UnpackOpts expect the message to be signed by the same DID who encrypted it,
        but it was signed by another DID
        :raises NotDecryptedByAllKeysException: if UnpackOpts expect the message to be decryptable by all keys resolved by the secrets resolver,
        but there were keys resolved for which decryption wasn't successful

        :param msg: the message as JSON string to be unpacked
        :return: the plaintext, metadata, and optionally a JWS if the plaintext has been signed.
        """
        return UnpackResult(
            plaintext=Plaintext(body={}, id="", type=""),
            metadata=Metadata(),
            signed_plaintext=None
        )
