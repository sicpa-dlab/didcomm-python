from __future__ import annotations

from typing import List, Optional

from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.algorithms import AnonCryptAlg, AuthCryptAlg, SignAlg
from didcomm.types.plaintext import Plaintext
from didcomm.types.types import JSON, DID, DID_OR_KID


class Packer:
    """Packer of plaintext DIDComm messages."""

    def __init__(self,
                 secrets_resolver: SecretsResolver,
                 did_resolver: DIDResolver):
        """Creates a Packer instance."""
        pass

    async def sign(self,
                   plaintext: Plaintext,
                   frm: DID_OR_KID,
                   sign_alg: SignAlg) -> JSON:
        """Packs the plaintext DIDComm message to sing(plain) format."""
        return ""

    async def anon_crypt(self,
                         plaintext: Plaintext,
                         to: List[DID],
                         enc_alg: AnonCryptAlg) -> JSON:
        """Packs the plaintext DIDComm message to anoncrypt(plain) format."""
        return ""

    async def auth_crypt(self,
                         plaintext: Plaintext,
                         frm: DID_OR_KID,
                         to: List[DID],
                         enc_alg: AuthCryptAlg) -> JSON:
        """Packs the plaintext DIDComm message to authcrypt(plain) format."""
        return ""

    async def anon_auth_crypt(self,
                              plaintext: Plaintext,
                              frm: DID_OR_KID,
                              to: List[DID],
                              authcrypt_alg: AuthCryptAlg,
                              anoncrypt_alg: AnonCryptAlg) -> JSON:
        """Packs the plaintext DIDComm message to anoncrypt(authcrypt(plain)) format."""
        return ""

    async def anon_crypt_signed(self,
                                plaintext: Plaintext,
                                frm: DID_OR_KID,
                                sign_alg: SignAlg,
                                to: List[DID],
                                enc_alg: AnonCryptAlg) -> JSON:
        """Packs the plaintext DIDComm message to anoncrypt(sign(plain)) format."""
        return ""

    async def auth_crypt_signed(self,
                                plaintext: Plaintext,
                                sign_frm: DID_OR_KID,
                                sign_alg: SignAlg,
                                enc_frm: DID_OR_KID,
                                enc_to: List[DID],
                                enc_alg: AuthCryptAlg) -> JSON:
        """Packs the plaintext DIDComm message to authcrypt(sign(plain)) format."""
        return ""

    async def anon_auth_crypt_signed(self,
                                     plaintext: Plaintext,
                                     sign_frm: DID_OR_KID,
                                     sign_alg: SignAlg,
                                     enc_from: DID_OR_KID,
                                     enc_to: List[DID],
                                     authcrypt_alg: AnonCryptAlg,
                                     anoncrypt_alg: AuthCryptAlg) -> JSON:
        """Packs the plaintext DIDComm message to anoncrypt(authcrypt(sign(plain))) format."""
        return ""
