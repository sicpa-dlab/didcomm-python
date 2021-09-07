from collections import namedtuple
from enum import Enum

Algs = namedtuple("Algs", ["alg", "enc"])


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

    A256CBC_HS512_ECDH_ES_A256KW = Algs(alg="ECDH-ES+A256KW", enc="A256CBC-HS512")
    XC20P_ECDH_ES_A256KW = Algs(alg="ECDH-ES+A256KW", enc="XC20P")
    A256GCM_ECDH_ES_A256KW = Algs(alg="ECDH-ES+A256KW", enc="A256GCM")


class AuthCryptAlg(Enum):
    """
    Algorithms for authentication encryption.

    Attributes:
        A256CBC_HS512_ECDH_1PU_A256KW: AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
        ECDH-1PU key agreement with A256KW key wrapping
    """

    A256CBC_HS512_ECDH_1PU_A256KW = Algs(alg="ECDH-1PU+A256KW", enc="A256CBC-HS512")


class SignAlg(Enum):
    """
    Algorithms for signature (non-repudiation)

    Attributes:
        ED25519: Elliptic curve digital signature with edwards curves Ed25519 and SHA-512
        ES256: Elliptic curve digital signature with NIST p-256 curve and SHA-256
        ES256K: Elliptic curve digital signature with Secp256k1 keys
    """

    ED25519 = "EdDSA"
    ES256 = "ES256"
    ES256K = "ES256K"
