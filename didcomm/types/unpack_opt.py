from typing import NamedTuple


class UnpackOpts(NamedTuple):
    """Message trust context for unpack operation."""
    expect_signed: bool = False
    expect_encrypted: bool = False
    expect_authenticated: bool = False
    expect_sender_hidden: bool = False
    expect_signed_by_encrypter: bool = True
    expect_decrypt_by_all_keys: bool = False
