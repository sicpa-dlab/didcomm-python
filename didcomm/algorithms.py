from enum import Enum


class KWAlgAuthCrypt(Enum):
    ECDH_1PU_A256KW = 2


class KWAlgAnonCrypt(Enum):
    ECDH_ES_A256KW = 1


class EncAlgAnonCrypt(Enum):
    A256CBC_HS512 = 1
    XC20P = 2
    A256GCM = 3


class EncAlgAuthCrypt(Enum):
    A256CBC_HS512 = 1
