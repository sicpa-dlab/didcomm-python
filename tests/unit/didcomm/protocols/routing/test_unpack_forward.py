import pytest

from didcomm.errors import MalformedMessageError
from didcomm.common.types import DID
from didcomm.core.defaults import DEF_ENC_ALG_ANON
from didcomm.core.types import UnpackAnoncryptResult
from didcomm.core.serialization import dict_to_json_bytes, dict_to_json
from didcomm.protocols.routing import forward
from didcomm.protocols.routing.forward import (
    unpack_forward,
    ForwardMessage,
    ForwardResult,
)


@pytest.fixture
def unpack_anoncrypt_result(did: DID, fwd_msg: ForwardMessage) -> UnpackAnoncryptResult:
    return UnpackAnoncryptResult(
        msg=dict_to_json_bytes(fwd_msg.as_dict()),
        to_kids=[did, did + "2"],
        alg=DEF_ENC_ALG_ANON,
    )


@pytest.fixture
def unpack_anoncrypt_mock(mocker, unpack_anoncrypt_result: UnpackAnoncryptResult):
    mock = mocker.patch.object(forward, "unpack_anoncrypt", autospec=True)
    mock.return_value = unpack_anoncrypt_result
    return mock


@pytest.fixture
def any_msg_dict():
    return {"we": "dontcare"}


@pytest.fixture
def any_msg_json(any_msg_dict):
    return dict_to_json(any_msg_dict)


# THE TESTS


@pytest.mark.asyncio
async def test_unpack_forward__unpack_anoncrypt_callspec(
    resolvers_config_mock, unpack_anoncrypt_mock, any_msg_dict, any_msg_json
):
    # to make the logic here: we just check the callspec
    unpack_anoncrypt_mock.side_effect = TypeError
    callspec = (any_msg_dict, resolvers_config_mock, True)
    try:
        await unpack_forward(resolvers_config_mock, any_msg_json, True)
    except TypeError:
        unpack_anoncrypt_mock.assert_called_once_with(*callspec)


@pytest.mark.asyncio
async def test_unpack_forward__no_forward_packed(
    resolvers_config_mock, unpack_anoncrypt_result, unpack_anoncrypt_mock
):
    # to hack / workaround Attachment frozen setting
    object.__setattr__(
        unpack_anoncrypt_result, "msg", dict_to_json_bytes({"key": "value"})
    )
    with pytest.raises(MalformedMessageError):
        await unpack_forward(
            resolvers_config_mock, dict_to_json({"we": "dontcare"}), True
        )


@pytest.mark.asyncio
async def test_unpack_forward__return(
    resolvers_config_mock,
    unpack_anoncrypt_mock,
    unpack_anoncrypt_result,
    any_msg_json,
    fwd_msg,
):
    res = await unpack_forward(resolvers_config_mock, any_msg_json, True)

    assert isinstance(res, ForwardResult)
    assert res.forward_msg == fwd_msg
    assert res.forwarded_msg == fwd_msg.attachments[0].data.json
    assert res.forwarded_msg_encrypted_to == unpack_anoncrypt_result.to_kids
