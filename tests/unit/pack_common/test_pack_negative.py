import pytest

from didcomm.errors import DIDCommValueError
from didcomm.message import Message
from didcomm.pack_plaintext import pack_plaintext
from didcomm.pack_signed import pack_signed
from tests.test_vectors.common import ALICE_DID


@pytest.mark.asyncio
async def test_pack_plaintext_no_id(resolvers_config_bob):
    msg = Message(
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        body={},
    )
    with pytest.raises(DIDCommValueError):
        await pack_plaintext(resolvers_config_bob, msg)
    with pytest.raises(DIDCommValueError):
        await pack_signed(resolvers_config_bob, msg, ALICE_DID)
    with pytest.raises(DIDCommValueError):
        await pack_signed(resolvers_config_bob, msg, ALICE_DID)


@pytest.mark.asyncio
async def test_pack_plaintext_no_body(resolvers_config_bob):
    pass


@pytest.mark.asyncio
async def test_pack_plaintext_no_type(resolvers_config_bob):
    pass


@pytest.mark.asyncio
async def test_pack_plaintext_custom_header_equals_to_default(resolvers_config_bob):
    pass
