import pytest
import attr
from typing import List

from didcomm.common.types import JSON_OBJ, DID_OR_DID_URL
from didcomm.did_doc.did_doc import DIDDoc, DIDCommService
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.algorithms import AnonCryptAlg

from didcomm import pack_encrypted
from didcomm.pack_encrypted import (
    PackEncryptedConfig,
    PackEncryptedParameters,
    __forward_if_needed,
)

from tests import mock_module


@pytest.fixture
def did_doc(did) -> DIDDoc:
    return DIDDoc(did, [], [], [], [])


@pytest.fixture
def wrap_in_forward_mock(mocker) -> mock_module.AsyncMock:
    return mocker.patch.object(pack_encrypted, "wrap_in_forward")


@attr.s(auto_attribs=True)
class _TestData:
    resolvers_config: ResolversConfig
    packed_msg: JSON_OBJ
    to: DID_OR_DID_URL
    did_services_chain: List[DIDCommService]
    pack_config: PackEncryptedConfig
    pack_params: PackEncryptedParameters


@pytest.fixture
def test_data(resolvers_config_mock, didcomm_service, pack_config, pack_params):
    msg = "somemsg"
    to = "someto"

    def id_gen_func():
        return "123"

    pack_config.enc_alg_anon = AnonCryptAlg.XC20P_ECDH_ES_A256KW
    pack_params.forward_headers = ({"some": "header"},)
    pack_params.forward_didcomm_id_generator = id_gen_func

    return _TestData(
        resolvers_config_mock, msg, to, [didcomm_service], pack_config, pack_params
    )


# ===================
# __forward_if_needed
# ===================


@pytest.mark.asyncio
async def test_forward_if_needed__forward_off(wrap_in_forward_mock, test_data):
    test_data.pack_config.forward = False
    res = await __forward_if_needed(**attr.asdict(test_data, recurse=False))
    assert res is None


@pytest.mark.asyncio
async def test_forward_if_needed__no_did_services(wrap_in_forward_mock, test_data):
    test_data.did_services_chain = []
    res = await __forward_if_needed(**attr.asdict(test_data, recurse=False))
    assert res is None


@pytest.mark.asyncio
async def test_forward_if_needed__no_routing_keys(wrap_in_forward_mock, test_data):
    test_data.did_services_chain[-1].routing_keys = []
    res = await __forward_if_needed(**attr.asdict(test_data, recurse=False))
    assert res is None


@pytest.mark.asyncio
async def test_forward_if_needed__single_service(wrap_in_forward_mock, test_data):
    await __forward_if_needed(**attr.asdict(test_data, recurse=False))

    wrap_in_forward_mock.assert_awaited_once_with(
        resolvers_config=test_data.resolvers_config,
        packed_msg=test_data.packed_msg,
        to=test_data.to,
        routing_keys=test_data.did_services_chain[0].routing_keys,
        enc_alg_anon=test_data.pack_config.enc_alg_anon,
        headers=test_data.pack_params.forward_headers,
        didcomm_id_generator=test_data.pack_params.forward_didcomm_id_generator,
    )


@pytest.mark.asyncio
async def test_forward_if_needed__multiple_services(
    didcomm_service1,
    didcomm_service2,
    didcomm_service3,
    wrap_in_forward_mock,
    test_data,
):
    test_data.did_services_chain = [
        didcomm_service2,
        didcomm_service3,
        didcomm_service1,
    ]
    exp_routing_keys = [
        didcomm_service3.service_endpoint,
        didcomm_service1.service_endpoint,
    ] + didcomm_service1.routing_keys

    await __forward_if_needed(**attr.asdict(test_data, recurse=False))

    wrap_in_forward_mock.assert_awaited_once_with(
        resolvers_config=test_data.resolvers_config,
        packed_msg=test_data.packed_msg,
        to=test_data.to,
        routing_keys=exp_routing_keys,
        enc_alg_anon=test_data.pack_config.enc_alg_anon,
        headers=test_data.pack_params.forward_headers,
        didcomm_id_generator=test_data.pack_params.forward_didcomm_id_generator,
    )
