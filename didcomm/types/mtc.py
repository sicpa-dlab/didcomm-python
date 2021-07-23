from __future__ import annotations

from typing import NamedTuple


class MTC(NamedTuple):
    expect_signed: bool = False
    expect_authcrypted: bool = False
    expect_anoncrypted: bool = False
    expect_signed_by_encrypter: bool = True
    expect_decrypt_by_all_keys: bool = False

    @staticmethod
    def build() -> MTCBuilder:
        return MTCBuilder()


class MTCBuilder:

    def finalize(self) -> MTC:
        return MTC()

    def expect_signed(self, value: bool = False) -> MTCBuilder:
        return self

    def expect_authcrypted(self, value: bool = False) -> MTCBuilder:
        return self

    def expect_anoncrypted(self, value: bool = False) -> MTCBuilder:
        return self

    def expect_signed_by_encrypter(self, value: bool = True) -> MTCBuilder:
        return self

    def expect_decrypt_by_all_keys(self, value: bool = False) -> MTCBuilder:
        return self
