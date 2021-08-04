from enum import Enum, auto


class AnonCryptAlg(Enum):
    """
    Algorithms for anonymous encryption.

    Attributes:
        A256CBC_HS512_ECDH_ES_A256KW: AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
        ECDH-ES key agreement with A256KW key wrapping

        XC20P_ECDH_ES_A256KW: XChaCha20Poly1305 with a 256 bit key content encryption,
        ECDH-ES key agreement with A256KW key wrapping

        A256GCM_ECDH_ES_A256KW: XChaCha20Poly1305 with a 256 bit key content encryption,
        ECDH-ES key agreement with A256KW key wrapping
    """
    A256CBC_HS512_ECDH_ES_A256KW = auto()
    XC20P_ECDH_ES_A256KW = auto()
    A256GCM_ECDH_ES_A256KW = auto()


class AuthCryptAlg(Enum):
    """
    Algorithms for authentication encryption.

    Attributes:
        A256CBC_HS512_ECDH_1PU_A256KW: AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
        ECDH-1PU key agreement with A256KW key wrapping
    """
    A256CBC_HS512_ECDH_1PU_A256KW = auto()
