from enum import Enum, auto


class SignAlg(Enum):
    """Available signature algorithms."""
    EdDSA = auto()
    ES256 = auto()
    ES256K = auto()


class AnonCryptAlg(Enum):
    """Available encryption / key agreement / key wrapping algorithms for anoncrypt."""
    XC20P_ECDH_ES_A256KW = auto()
    A256GCM_ECDH_ES_A256KW = auto()
    A256CBC_HS512_ECDH_ES_A256KW = auto()


class AuthCryptAlg(Enum):
    """Available encryption / key agreement / key wrapping algorithms for authcrypt."""
    A256CBC_HS512_ECDH_1PU_A256KW = auto()
