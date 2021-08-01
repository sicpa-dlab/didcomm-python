from typing import Optional, NamedTuple

from didcomm.types.algorithms import SignAlg
from didcomm.types.types import DID, KID, JWS


class FromPrior(NamedTuple):
    """from_prior property of a plaintext."""
    iss: DID
    sub: DID
    aud: Optional[str] = None
    exp: Optional[int] = None
    nbf: Optional[int] = None
    iat: Optional[int] = None
    jti: Optional[str] = None

    def as_jws(self, sign_alg: SignAlg, iss_kid: KID = None) -> JWS:
        """Gets the signed JWT with this FromPrior information.

        :param sign_alg: the signature algorithm to use for signing the JWT
        :param iss_kid: the specific key ID to sign the JWT
        :returns: the JWS being the signed JWT with this FromPrior information
        """
        pass
