from didcomm.errors import DIDCommException


class ForwardException(DIDCommException):
    pass


class InvalidForwardPackException(ForwardException):
    pass


class NotForwardTypeException(ForwardException):
    pass
