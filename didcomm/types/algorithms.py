from enum import Enum


class AnonCryptAlg(Enum):
    A256CBC_HS512_ECDH_ES_A256KW = 1
    XC20P_ECDH_ES_A256KW = 2
    A256GCM_ECDH_ES_A256KW = 3


class AuthCryptAlg(Enum):
    A256CBC_HS512_ECDH_1PU_A256KW = 1
