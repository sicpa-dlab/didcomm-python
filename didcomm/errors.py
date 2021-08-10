from enum import Enum


# TODO: finalize exceptions during development

class DIDCommError(Exception):
    pass


class DIDNotResolvedError(DIDCommError):
    pass


class SecretNotResolvedError(DIDCommError):
    pass


class IncompatibleKeysError(DIDCommError):
    pass


class MalformedMessageCode(Enum):
    CAN_NOT_DECRYPT = 1
    INVALID_SIGNATURE = 2
    INVALID_PLAINTEXT = 3


class MalformedMessageError(DIDCommError):

    def __init__(self, code: MalformedMessageCode):
        self.code = code


class UnexpectedPackCode(Enum):
    NOT_ENCRYPTED = 1
    NOT_AUTHENTICATED = 2
    NOT_SIGNED = 3
    SENDER_NOT_PROTECTED = 4
    NOT_SIGNED_BY_ENCRYPTER = 5
    NOT_DECRYPTED_BY_ALL_KEYS = 6


class UnexpectedPackError(DIDCommError):
    def __init__(self, code: UnexpectedPackCode):
        self.code = code
