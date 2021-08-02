from __future__ import annotations

from dataclasses import dataclass
from typing import List

from didcomm.common.types import DID_OR_KID, JSON_DATA, JWK, JSON
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.plaintext import Plaintext, PlaintextHeaders
from didcomm.secrets.secrets_resolver import SecretsResolver
from didcomm.unpack import UnpackOpts


@dataclass(frozen=True)
class ForwardBody:
    next: DID_OR_KID
    forwarded_msg: JSON


@dataclass(frozen=True)
class ForwardPlaintext(PlaintextHeaders, ForwardBody):
    pass


class Forwarder:
    def __init__(self, secrets_resolver: SecretsResolver = None, did_resolver: DIDResolver = None):
        pass

    async def pack_forward(self, packed_msg: JSON_DATA, routing_keys: List[JWK]) -> JSON:
        return ""

    async def unpack_forward(self, msg: JSON) -> ForwardPlaintext:
        return ForwardPlaintext(
            next="",
            forwarded_msg="",
            id="", type="")

    @staticmethod
    def parse_forward(plaintext: Plaintext) -> ForwardPlaintext:
        return ForwardPlaintext(
            next="",
            forwarded_msg="",
            id="", type="")

    @staticmethod
    def is_forward(plaintext: Plaintext) -> bool:
        return True

    @staticmethod
    def build_forward_unpack_opts() -> UnpackOpts:
        return UnpackOpts(
            expect_signed=False,
            expect_encrypted=True,
            expect_authenticated=False,
            expect_decrypt_by_all_keys=False,
            unwrap_re_wrapping_forward=True
        )
