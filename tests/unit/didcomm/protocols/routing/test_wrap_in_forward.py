import pytest
import dataclasses

from didcomm.common.types import DID, DIDCommMessageProtocolTypes
from didcomm.core.types import EncryptResult
from didcomm.protocols.routing import forward
from didcomm.protocols.routing.forward import (
    wrap_in_forward,
    ForwardBody,
    ForwardPackResult,
)


@pytest.fixture
def encrypted_msg1() -> dict:
    return {"some": "dict1"}


@pytest.fixture
def encrypted_msg2() -> dict:
    return {"some": "dict2"}


@pytest.fixture
def encrypt_result1(did: DID, encrypted_msg1: dict) -> EncryptResult:
    return EncryptResult(
        msg=encrypted_msg1, to_kids=[did], to_keys=["not", "important", "for", "now"]
    )


@pytest.fixture
def encrypt_result2(
    encrypt_result1: EncryptResult, encrypted_msg2: dict
) -> EncryptResult:
    return dataclasses.replace(encrypt_result1, msg=encrypted_msg2)


@pytest.fixture
def find_keys_and_anoncrypt_mock(
    mocker, encrypt_result1: EncryptResult, encrypt_result2: EncryptResult
):
    mock = mocker.patch.object(forward, "find_keys_and_anoncrypt")
    # will help for cases with multiple routing keys (multiple calls)
    side_effect = (encrypt_result1, encrypt_result2)
    mock.side_effect = side_effect
    # the above one would be an iterator and can't be used for assertions
    mock._side_effect = side_effect
    return mock


@pytest.fixture
def callspec(resolvers_config_mock, did1, did2, did3):
    return dict(
        resolvers_config=resolvers_config_mock,
        packed_msg={"dont": "care"},
        to=did3,
        routing_keys=[did1, did2],
        enc_alg_anon="some_enc_alg",
        headers={"some": "headers"},
        didcomm_id_generator=lambda: 123,
    )


# THE TESTS


@pytest.mark.asyncio
async def test_wrap_in_forward__no_routing_keys(callspec):
    callspec["routing_keys"] = []
    assert await wrap_in_forward(**callspec) is None


@pytest.mark.asyncio
async def test_wrap_in_forward__forward_message_callspec(mocker, callspec):
    # TODO use autospec=True need to explore why it doesn"t work
    #      (stats for calls is not callected)
    att_mock = mocker.patch.object(forward, "Attachment")
    att_mock.return_value = "fwd-attachment"

    # to make the logic here: we just check the callspec
    fw_mock = mocker.patch.object(forward, "ForwardMessage")
    fw_mock.side_effect = TypeError

    try:
        await wrap_in_forward(**callspec)
    except TypeError:
        fw_mock.assert_called_once_with(
            id=callspec["didcomm_id_generator"],
            body=ForwardBody(next=callspec["to"]),
            type=DIDCommMessageProtocolTypes.FORWARD.value,
            attachments=[att_mock.return_value],
            **callspec["headers"],
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("routing_keys_num", range(1, 3), ids=["simple", "recursive"])
async def test_wrap_in_forward__return(
    mocker, did1, did2, did3, find_keys_and_anoncrypt_mock, callspec, routing_keys_num
):
    routing_keys = [did1, did2][:routing_keys_num]
    tos = routing_keys[::-1]
    nexts = (routing_keys[1:] + [did3])[::-1]

    fw_mock = mocker.patch.object(forward, "ForwardMessage")
    fw_mock_side_effect = [mocker.Mock(), mocker.Mock()]
    fw_mock.side_effect = fw_mock_side_effect
    for i, m in enumerate(fw_mock_side_effect):
        m.as_dict.return_value = {"some": {"fwd": f"msg{i}"}}

    att_mock = mocker.patch.object(forward, "Attachment")
    att_mock_side_effect = ["att1", "att2"]
    att_mock.side_effect = att_mock_side_effect

    callspec["routing_keys"] = routing_keys

    res = await wrap_in_forward(**callspec)

    assert find_keys_and_anoncrypt_mock.call_count == len(routing_keys)

    for i, (_to, _next) in enumerate(zip(tos, nexts)):
        assert fw_mock.call_args_list[i] == mocker.call(
            id=callspec["didcomm_id_generator"],
            body=ForwardBody(next=_next),
            type=DIDCommMessageProtocolTypes.FORWARD.value,
            attachments=[att_mock_side_effect[i]],
            **callspec["headers"],
        )
        assert find_keys_and_anoncrypt_mock.call_args_list[i] == mocker.call(
            fw_mock_side_effect[i].as_dict.return_value,
            _to,
            callspec["enc_alg_anon"],
            callspec["resolvers_config"],
        )

    assert isinstance(res, ForwardPackResult)
    assert res.msg == fw_mock_side_effect[routing_keys_num - 1]
    assert (
        res.msg_encrypted
        == find_keys_and_anoncrypt_mock._side_effect[routing_keys_num - 1]
    )
