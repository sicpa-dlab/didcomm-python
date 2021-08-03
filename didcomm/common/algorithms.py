from enum import Enum, auto


class AnonCryptAlg(Enum):
    """
    Algorithms for anonymous encryption.
    It has a form <content-encryption-algorithm>_<key-agreement-algorithm>_<key-wrapping-algorithm>.
    """
    A256CBC_HS512_ECDH_ES_A256KW = auto()
    XC20P_ECDH_ES_A256KW = auto()
    A256GCM_ECDH_ES_A256KW = auto()


class AuthCryptAlg(Enum):
    """
    Algorithms for authentication encryption.
    It has a form <content-encryption-algorithm>_<key-agreement-algorithm>_<key-wrapping-algorithm>.
    """
    A256CBC_HS512_ECDH_1PU_A256KW = auto()
