class DIDCommException(Exception):
    pass


# Common
class UnknownRecipientException(DIDCommException):
    pass


class UnknownSenderException(DIDCommException):
    pass


class NoJWKKeyException(DIDCommException):
    pass


# Crypto
class IncompatibleKeysException(DIDCommException):
    pass


class InvalidSignatureException(DIDCommException):
    pass


class CanNotDecryptException(DIDCommException):
    pass


# DID Doc exceptions

class DIDDocException(DIDCommException):
    pass


class NoKeyAgreementException(DIDDocException):
    pass


class NoAuthenticationException(DIDDocException):
    pass


# Pack exceptions
class PackException(DIDCommException):
    pass


class FromEncryptNotSet(DIDCommException):
    pass


class FromSignNotSet(DIDCommException):
    pass


# Unpack exceptions

class UnpackException(DIDCommException):
    pass


class NotSignedException(UnpackException):
    pass


class NotEncryptedException(UnpackException):
    pass


class NotAuthenticatedException(UnpackException):
    pass


class SenderNotHiddenException(UnpackException):
    pass


class NotSignedByEncrypterException(UnpackException):
    pass


class NotDecryptedByAllKeysException(UnpackException):
    pass


