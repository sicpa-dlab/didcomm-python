from enum import Enum, auto


class AnonCryptAlg(Enum):
    A256CBC_HS512_ECDH_ES_A256KW = auto()
    XC20P_ECDH_ES_A256KW = auto()
    A256GCM_ECDH_ES_A256KW = auto()


class AuthCryptAlg(Enum):
    A256CBC_HS512_ECDH_1PU_A256KW = auto()
