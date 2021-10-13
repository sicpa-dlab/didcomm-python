from enum import Enum


class DIDCommError(Exception):
    pass


class DIDCommValueError(DIDCommError, ValueError):
    pass


class DIDDocNotResolvedError(DIDCommError):
    pass


class DIDUrlNotFoundError(DIDCommError):
    pass


class SecretNotFoundError(DIDCommError):
    pass


class IncompatibleCryptoError(DIDCommError):
    pass


class InvalidDIDDocError(DIDCommValueError):
    pass


class MalformedMessageCode(Enum):
    CAN_NOT_DECRYPT = 1
    INVALID_SIGNATURE = 2
    INVALID_PLAINTEXT = 3
    INVALID_MESSAGE = 4
    NOT_SUPPORTED_FWD_PROTOCOL = 5


class MalformedMessageError(DIDCommError):
    def __init__(self, code: MalformedMessageCode, message: str = None):
        self.code = code

        if message is not None:
            self.message = message
        else:
            if self.code == MalformedMessageCode.CAN_NOT_DECRYPT:
                self.message = "DIDComm message cannot be decrypted"
            elif self.code == MalformedMessageCode.INVALID_SIGNATURE:
                self.message = "Signature is invalid"
            elif self.code == MalformedMessageCode.INVALID_PLAINTEXT:
                self.message = "Plaintext is invalid"
            elif self.code == MalformedMessageCode.INVALID_MESSAGE:
                self.message = "DIDComm message is invalid"
            elif self.code == MalformedMessageCode.NOT_SUPPORTED_FWD_PROTOCOL:
                self.message = "Not supported Forward protocol"
