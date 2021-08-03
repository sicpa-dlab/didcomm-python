from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional, Dict

from didcomm.common.types import JSON, DID_OR_KID, DID
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.plaintext import Plaintext
from didcomm.secrets.secrets_resolver import SecretsResolver


class AnonCryptAlg(Enum):
    """
    Algorithms for anonymous encryption.
    Usually has a form <content-encryption-algorithm>_<key-agreement-algorithm>_<key-wrapping-algorithm>.
    """
    A256CBC_HS512_ECDH_ES_A256KW = auto()
    XC20P_ECDH_ES_A256KW = auto()
    A256GCM_ECDH_ES_A256KW = auto()


class AuthCryptAlg(Enum):
    """
    Algorithms for authentication encryption.
    Usually has a form <content-encryption-algorithm>_<key-agreement-algorithm>_<key-wrapping-algorithm>.
    """
    A256CBC_HS512_ECDH_1PU_A256KW = auto()


@dataclass(frozen=True)
class PackedForward:
    packed_forward_msg: JSON
    service_endpoint: str


@dataclass(frozen=True)
class PackResult:
    packed_msg: JSON
    packed_forward_msgs: Optional[Dict[DID, PackedForward]]


class Packer:
    """
    Prepares a plaintext for sending by packing and wrapping the packed message in Forward messages for every recipient
    as defined by the Forward protocol.
    Packing is a combination of optional sign and/or encrypt operations.
    """

    def __init__(self, secrets_resolver: SecretsResolver = None, did_resolver: DIDResolver = None,
                 forward: bool = True):
        """
        A new instance of Packer.

        :param secrets_resolver: an optional secrets resolver that can override a default secrets resolver
        registered by 'register_default_secrets_resolver'
        :param did_resolver: an optional DID Doc resolver that can override a default DID Doc resolver
        registered by 'register_default_did_resolver'
        :param forward: whether a packed message will be wrapped in Forward messages for every recipient
        as defined by the Forward protocol. True by default.
        """
        pass

    async def pack_plaintext(self, msg: Plaintext) -> PackResult:
        """
        Packs the plaintext without signing and encryption.

        Serializes the plaintext to JSON and optionally wraps in Forward messages for every recipient
        as defined by the Forward protocol.
        Wrapping in Forward is done if 'forward' argument in constructor is True (which is default).

        :param msg: the plaintext to be packed
        :return: a pack result consisting of a packed message as a JSON string and an optional dict of forward result
        for every recipient DID if forward is enabled.
        """
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def sign(self, msg: Plaintext, frm: DID_OR_KID = None) -> PackResult:
        """
        Signs the plaintext without encryption.

        The method does the following:
        1) Signs the plaintext as JWS
        2) Optionally wraps in Forward messages for every recipient as defined by the Forward protocol.
        Wrapping in Forward is done if 'forward' argument in constructor is True (which is default).

        Signing is done as follows:
        - if 'frm' DID or key ID is specified, then this DID or KID is used for signing.
        Otherwise a DID or key ID from the `from` plaintext header is used.
        - signing is done via the keys from the `authentication` verification relationship in the DID Doc
        for the DID to be used for signing
        - if DID is used for signing, then the first `authentication` verification method
        for which there is a private key in the secrets resolver is used
        - if Key ID is used for signing, the `authentication` verification method identified by the given key ID is used

        :param msg: the plaintext to be signed
        :param frm: an optional DID or keyID to be used for signing. If not specified, then `from` header in Plaintext is used.
        :return: a pack result consisting of a packed message as a JSON string and an optional dict of forward result
        for every recipient DID if forward is enabled.
        """
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def anon_crypt(self, msg: Plaintext, enc_alg: AnonCryptAlg,
                         to_dids: List[DID] = None) -> PackResult:
        """
        Performs encryption without authenticating the sender.

        The method does the following:
        1) Encrypts the plaintext as JWE keeping the sender unknown (anonymous)
        2) Optionally wraps in Forward messages for every recipient as defined by the Forward protocol.
        Wrapping in Forward is done if 'forward' argument in constructor is True (which is default).

        Anonymous encryption is done as follows:
        - if `to_dids` is specified, then these recipient DIDs are used as a target.
        Otherwise a DID or key ID from the `to` plaintext header is used.
        - encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
        - multiplex encryption is done for all keys from the receiver's `keyAgreement` verification relationship


        :param msg: the plaintext to be encrypted
        :param enc_alg: the encryption algorithm to be used
        :param to_dids: an optional list of recipient DIDs. If not specified, then `to` header in Plaintext is used.
        :return: a pack result consisting of a packed message as a JSON string and an optional dict of forward result
        for every recipient DID if forward is enabled.
        """
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def auth_crypt(self, msg: Plaintext,
                         frm: DID_OR_KID = None, to_dids: List[DID] = None,
                         enc_alg: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> PackResult:
        """
        Performs authentication encryption keeping the sender disclosed.

        The method does the following:
        1) Performs authenticated encryption as JWE
        2) Optionally wraps in Forward messages for every recipient as defined by the Forward protocol.
        Wrapping in Forward is done if 'forward' argument in constructor is True (which is default).

        Authenticated encryption is done as follows:
        - if 'frm' DID or key ID is specified, then this sender DID or KID is used for authentication encryption.
        Otherwise a DID or key ID from the `from` plaintext header is used.
        - if `to_dids` is specified, then these recipient DIDs are used as a target.
        Otherwise a DID or key ID from the `to` plaintext header is used.
        - encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
        - if sender's DID is used for encryption, then the first `keyAgreement` verification method
        for which there is a private key in the secrets resolver is used
        - if sender's Key ID is used for encryption, the `keyAgreement` verification method identified by the given key ID is used.
        - multiplex encryption is done for all keys from the receiver's `keyAgreement` verification relationship

        :param msg: the plaintext to be encrypted
        :param frm: an optional sender's DID or keyID to be used for encryption. If not specified, then `from` header in Plaintext is used.
        :param to_dids: an optional list of recipient DIDs. If not specified, then `to` header in Plaintext is used.
        :param enc_alg: the encryption algorithm to be used. `A256CBC_HS512_ECDH_1PU_A256KW` by default.
        :return: a pack result consisting of a packed message as a JSON string and an optional dict of forward result
        for every recipient DID if forward is enabled.
        """
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def anon_auth_crypt(self, msg: Plaintext, enc_alg_anon: AnonCryptAlg,
                              frm: DID_OR_KID = None, to_dids: List[DID] = None,
                              enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> PackResult:
        """
        Performs authentication encryption keeping the sender anonymous.

        The method does the following:
        1) Performs authenticated encryption as JWE
        2) Performs anonymous encryption for the result of authenticated encryption, which hides the sender
        3) Optionally wraps in Forward messages for every recipient as defined by the Forward protocol.
        Wrapping in Forward is done if 'forward' argument in constructor is True (which is default).

        Authenticated encryption is done as follows:
        - if 'frm' DID or key ID is specified, then this sender DID or KID is used for authentication encryption.
        Otherwise a DID or key ID from the `from` plaintext header is used.
        - if `to_dids` is specified, then these recipient DIDs are used as a target.
        Otherwise a DID or key ID from the `to` plaintext header is used.
        - encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
        - if sender's DID is used for encryption, then the first `keyAgreement` verification method
        for which there is a private key in the secrets resolver is used
        - if sender's Key ID is used for encryption, the `keyAgreement` verification method identified by the given key ID is used.
        - multiplex encryption is done for all keys from the receiver's `keyAgreement` verification relationship

        Anonymous encryption is done as follows:
        - The same recipient DIDs or keyIDs are used as for authenticated encryption
        - multiplex encryption is done for all keys from the receiver's `keyAgreement` verification relationship

        :param msg: the plaintext to be encrypted
        :param enc_alg_anon: the anonymous encryption algorithm to be used
        :param frm: an optional sender's DID or keyID to be used for encryption. If not specified, then `from` header in Plaintext is used.
        :param to_dids: an optional list of recipient DIDs. If not specified, then `to` header in Plaintext is used.
        :param enc_alg_auth: the authenticated encryption algorithm to be used. `A256CBC_HS512_ECDH_1PU_A256KW` by default.
        :return: a pack result consisting of a packed message as a JSON string and an optional dict of forward result
        for every recipient DID if forward is enabled.
        """
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def anon_crypt_signed(self, msg: Plaintext, enc_alg: AnonCryptAlg,
                                frm: DID_OR_KID = None, to_dids: List[DID] = None) -> PackResult:
        """
        Signs and then encrypts. Can be used as alternative authentication encryption or for non-repudiation.

        The method does the following:
        1) Signs the plaintext as JWS
        2) Encrypts the JWS as JWE keeping the sender unknown (anonymous)
        3) Optionally wraps in Forward messages for every recipient as defined by the Forward protocol.
        Wrapping in Forward is done if 'forward' argument in constructor is True (which is default).

        Signing is done as follows:
        - if 'frm' DID or key ID is specified, then this DID or KID is used for signing.
        Otherwise a DID or key ID from the `from` plaintext header is used.
        - signing is done via the keys from the `authentication` verification relationship in the DID Doc
        for the DID to be used for signing
        - if DID is used for signing, then the first `authentication` verification method
        for which there is a private key in the secrets resolver is used
        - if Key ID is used for signing, the `authentication` verification method identified by the given key ID is used

        Anonymous encryption is done as follows:
        - if `to_dids` is specified, then these recipient DIDs are used as a target.
        Otherwise a DID or key ID from the `to` plaintext header is used.
        - encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
        - multiplex encryption is done for all keys from the receiver's `keyAgreement` verification relationship


        :param msg: the plaintext to be signed and encrypted
        :param enc_alg: the encryption algorithm to be used
        :param frm: an optional DID or keyID to be used for signing. If not specified, then `from` header in Plaintext is used.
        :param to_dids: an optional list of recipient DIDs. If not specified, then `to` header in Plaintext is used.
        :return: a pack result consisting of a packed message as a JSON string and an optional dict of forward result
        for every recipient DID if forward is enabled.
        """
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def auth_crypt_signed(self, msg: Plaintext,
                                frm_enc: DID_OR_KID = None, to_dids: List[DID] = None,
                                frm_sign: Optional[DID_OR_KID] = None,
                                enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> PackResult:
        """
        Signs and then performs authentication encrypts. Can be used for non-repudiation.

        The method does the following:
        1) Signs the plaintext as JWS
        2) Performs authentication encryption of the JWS as JWE keeping the sender disclosed
        3) Optionally wraps in Forward messages for every recipient as defined by the Forward protocol.
        Wrapping in Forward is done if 'forward' argument in constructor is True (which is default).

        Signing is done as follows:
        - if 'frm' DID or key ID is specified, then this DID or KID is used for signing.
        Otherwise a DID or key ID from the `from` plaintext header is used.
        - signing is done via the keys from the `authentication` verification relationship in the DID Doc
        for the DID to be used for signing
        - if DID is used for signing, then the first `authentication` verification method
        for which there is a private key in the secrets resolver is used
        - if Key ID is used for signing, the `authentication` verification method identified by the given key ID is used

        Authenticated encryption is done as follows:
        - if 'frm' DID or key ID is specified, then this sender DID or KID is used for authentication encryption.
        Otherwise a DID or key ID from the `from` plaintext header is used.
        - if `to_dids` is specified, then these recipient DIDs are used as a target.
        Otherwise a DID or key ID from the `to` plaintext header is used.
        - encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
        - if sender's DID is used for encryption, then the first `keyAgreement` verification method
        for which there is a private key in the secrets resolver is used
        - if sender's Key ID is used for encryption, the `keyAgreement` verification method identified by the given key ID is used.
        - multiplex encryption is done for all keys from the receiver's `keyAgreement` verification relationship


        :param msg: the plaintext to be signed and encrypted
        :param frm_enc: an optional sender's DID or keyID to be used for encryption. If not specified, then `from` header in Plaintext is used.
        :param frm_sign: an optional DID or keyID to be used for signing. If not specified, then `from` header in Plaintext is used.
        :param to_dids: an optional list of recipient DIDs. If not specified, then `to` header in Plaintext is used.
        :param enc_alg_auth: the authenticated encryption algorithm to be used. `A256CBC_HS512_ECDH_1PU_A256KW` by default.
        :return: a pack result consisting of a packed message as a JSON string and an optional dict of forward result
        for every recipient DID if forward is enabled.
        """
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def anon_auth_crypt_signed(self, msg: Plaintext, enc_alg_anon: AnonCryptAlg,
                                     frm_enc: DID_OR_KID = None, to_dids: List[DID] = None,
                                     frm_sign: Optional[DID_OR_KID] = None,
                                     enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> PackResult:
        """
        Signs and then performs authentication encrypts keeping the sender anonymous. Can be used for non-repudiation.

        The method does the following:
        1) Signs the plaintext as JWS
        2) Performs authentication encryption of the JWS as JWE
        3) Performs anonymous encryption for the result of authenticated encryption, which hides the sender
        4) Optionally wraps in Forward messages for every recipient as defined by the Forward protocol.
        Wrapping in Forward is done if 'forward' argument in constructor is True (which is default).

        Signing is done as follows:
        - if 'frm' DID or key ID is specified, then this DID or KID is used for signing.
        Otherwise a DID or key ID from the `from` plaintext header is used.
        - signing is done via the keys from the `authentication` verification relationship in the DID Doc
        for the DID to be used for signing
        - if DID is used for signing, then the first `authentication` verification method
        for which there is a private key in the secrets resolver is used
        - if Key ID is used for signing, the `authentication` verification method identified by the given key ID is used

        Authenticated encryption is done as follows:
        - if 'frm' DID or key ID is specified, then this sender DID or KID is used for authentication encryption.
        Otherwise a DID or key ID from the `from` plaintext header is used.
        - if `to_dids` is specified, then these recipient DIDs are used as a target.
        Otherwise a DID or key ID from the `to` plaintext header is used.
        - encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
        - if sender's DID is used for encryption, then the first `keyAgreement` verification method
        for which there is a private key in the secrets resolver is used
        - if sender's Key ID is used for encryption, the `keyAgreement` verification method identified by the given key ID is used.
        - multiplex encryption is done for all keys from the receiver's `keyAgreement` verification relationship

        Anonymous encryption is done as follows:
        - The same recipient DIDs or keyIDs are used as for authenticated encryption
        - multiplex encryption is done for all keys from the receiver's `keyAgreement` verification relationship

        :param msg: the plaintext to be signed and encrypted
        :param enc_alg_anon: the anonymous encryption algorithm to be used
        :param frm_enc: an optional sender's DID or keyID to be used for encryption. If not specified, then `from` header in Plaintext is used.
        :param frm_sign: an optional DID or keyID to be used for signing. If not specified, then `from` header in Plaintext is used.
        :param to_dids: an optional list of recipient DIDs. If not specified, then `to` header in Plaintext is used.
        :param enc_alg_auth: the authenticated encryption algorithm to be used. `A256CBC_HS512_ECDH_1PU_A256KW` by default.
        :return: a pack result consisting of a packed message as a JSON string and an optional dict of forward result
        for every recipient DID if forward is enabled.
        """
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})
