from __future__ import annotations

from typing import NamedTuple, Optional

from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types import JSON, Payload, JWS, Metadata, DID


class UnpackResult(NamedTuple):
    payload: Payload
    metadata: Metadata
    signed_payload: Optional[JWS]
    frm: Optional[DID]


class UnpackBuilder:

    async def unpack(self, msg: JSON) -> UnpackResult:
        return UnpackResult(
            payload={},
            signed_payload="",
            metadata=Metadata(),
            frm=""
        )

    def did_resolver(self, did_resolver: DIDResolver) -> UnpackBuilder:
        return self

    def secrets_resolver(self, secrets_resolver: SecretsResolver) -> UnpackBuilder:
        return self

    def is_forward(self, value: bool = False) -> UnpackBuilder:
        return self

    def expect_signed(self, value: bool = False) -> UnpackBuilder:
        return self

    def expect_authcrypted(self, value: bool = False) -> UnpackBuilder:
        return self

    def expect_anoncrypted(self, value: bool = False) -> UnpackBuilder:
        return self

    def expect_signed_by_encrypter(self, value: bool = True) -> UnpackBuilder:
        return self

    def expect_decrypt_by_all_keys(self, value: bool = False) -> UnpackBuilder:
        return self
