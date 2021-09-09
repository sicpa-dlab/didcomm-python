import pytest

from didcomm.pack_signed import pack_signed
from didcomm.unpack import unpack
from tests.test_vectors.common import ALICE_DID
from tests.test_vectors.didcomm_messages.messages import (
    TEST_MESSAGE,
    minimal_msg,
    attachment_multi_1_msg,
    attachment_json_msg,
)
from tests.test_vectors.utils import get_auth_methods_in_secrets, Person


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "msg",
    [TEST_MESSAGE, minimal_msg(), attachment_multi_1_msg(), attachment_json_msg()],
)
@pytest.mark.parametrize(
    "sign_frm",
    [ALICE_DID] + [vm.id for vm in get_auth_methods_in_secrets(Person.ALICE)],
)
async def test_anoncrypt(msg, sign_frm, resolvers_config_alice, resolvers_config_bob):
    pack_result = await pack_signed(
        resolvers_config=resolvers_config_alice, message=msg, sign_frm=sign_frm
    )

    expected_sign_frm = get_auth_methods_in_secrets(Person.ALICE)[0].id
    if sign_frm != ALICE_DID:
        expected_sign_frm = sign_frm

    assert pack_result.sign_from_kid == expected_sign_frm
    assert pack_result.packed_msg is not None

    unpack_res = await unpack(
        resolvers_config=resolvers_config_bob, packed_msg=pack_result.packed_msg
    )
    assert unpack_res.message == msg
    assert unpack_res.metadata.non_repudiation
    assert unpack_res.metadata.enc_alg_anon is None
    assert unpack_res.metadata.enc_alg_auth is None
    assert not unpack_res.metadata.anonymous_sender
    assert not unpack_res.metadata.encrypted
    assert not unpack_res.metadata.re_wrapped_in_forward
    assert not unpack_res.metadata.authenticated
