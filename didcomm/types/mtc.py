from __future__ import annotations

from typing import NamedTuple


class MTC(NamedTuple):
    expect_signed: bool = False
    expect_authcrypted: bool = False
    expect_anoncrypted: bool = False
    expect_signed_by_encrypter: bool = True
    expect_decrypt_by_all_keys: bool = False

