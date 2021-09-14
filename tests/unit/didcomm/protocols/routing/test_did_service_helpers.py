import pytest
from unittest.mock import AsyncMock

from didcomm.common.types import DID
from didcomm.errors import (
    DIDDocNotResolvedError,
    InvalidDIDDocError
)
from didcomm.did_doc.did_doc import DIDDoc, DIDCommService
from didcomm.protocols.routing import forward  # for patch.object mocks
from didcomm.protocols.routing.forward import (
    find_did_service,
    resolve_did_services_chain
)


@pytest.fixture
def did_doc(did) -> DIDDoc:
    return DIDDoc(did, [], [], [], [])


# ===============
# find_did_service
# ===============

@pytest.mark.asyncio
async def test_find_did_service__no_diddoc(resolvers_config_mock, did_doc):
    resolve_mock = resolvers_config_mock.did_resolver.resolve
    resolve_mock.return_value = None

    with pytest.raises(DIDDocNotResolvedError):
        await find_did_service(resolvers_config_mock, did_doc.did)

    resolve_mock.assert_awaited_once_with(did_doc.did)


@pytest.mark.asyncio
async def test_find_did_service__no_service(resolvers_config_mock, did_doc):
    resolve_mock = resolvers_config_mock.did_resolver.resolve
    resolve_mock.return_value = did_doc

    res = await find_did_service(resolvers_config_mock, did_doc.did)
    assert res is None


@pytest.mark.asyncio
async def test_find_did_service__first_service(resolvers_config_mock, did_doc):
    resolve_mock = resolvers_config_mock.did_resolver.resolve

    service1 = {}
    did_doc.didcomm_services = [service1, 2, 3]
    resolve_mock.return_value = did_doc

    res = await find_did_service(resolvers_config_mock, did_doc.did)
    assert res is service1


@pytest.mark.asyncio
async def test_find_did_service__no_service_id(resolvers_config_mock, did_doc):
    resolve_mock = resolvers_config_mock.did_resolver.resolve
    resolve_mock.return_value = did_doc

    with pytest.raises(InvalidDIDDocError):
        await find_did_service(
            resolvers_config_mock, did_doc.did, service_id="did2")


@pytest.mark.asyncio
async def test_find_did_service__by_service_id(
    mocker, resolvers_config_mock, did_doc
):
    resolve_mock = resolvers_config_mock.did_resolver.resolve
    resolve_mock.return_value = did_doc

    service1 = mocker.Mock()
    service1.id = "123"

    service2 = mocker.Mock()
    service2.id = "456"

    did_doc.didcomm_services = [service1, service2]

    res = await find_did_service(
        resolvers_config_mock, did_doc.did, service_id=service2.id)
    assert res is service2


# ==========================
# resolve_did_services_chain
# ==========================

@pytest.fixture
def find_did_service_mock(mocker) -> AsyncMock:
    return mocker.patch.object(forward, "find_did_service")


@pytest.mark.asyncio
async def test_resolve_did_services_chain__no_service(
    resolvers_config_mock, did_doc, find_did_service_mock
):
    find_did_service_mock.return_value = None
    res = await resolve_did_services_chain(resolvers_config_mock, did_doc.did)
    assert res == []


@pytest.fixture
def didcomm_service():
    return DIDCommService("", "", [""], [""])


@pytest.mark.asyncio
async def test_resolve_did_services_chain__uri_as_endpoint(
    resolvers_config_mock, did_doc, find_did_service_mock, didcomm_service
):
    didcomm_service.service_endpoint = "https://some.domain"
    find_did_service_mock.return_value = didcomm_service
    res = await resolve_did_services_chain(resolvers_config_mock, did_doc.did)
    assert len(res) == 1
    assert res[0] is didcomm_service


@pytest.mark.asyncio
async def test_resolve_did_services_chain__did_as_endpoint(
    resolvers_config_mock, did1, did2, find_did_service_mock
):
    service1 = DIDCommService("", did1, [""], [""])
    service2 = DIDCommService("", "https://some.domain", [""], [""])
    expected_res = [service1, service2]

    find_did_service_mock.side_effect = (x for x in expected_res)

    res = await resolve_did_services_chain(resolvers_config_mock, did1)

    for i in range(len(expected_res)):
        assert res[i] is expected_res[i]


@pytest.mark.asyncio
async def test_resolve_did_services_chain__no_mediator_did_service(
    resolvers_config_mock, did1, did2, find_did_service_mock
):
    service1 = DIDCommService("", did1, [""], [""])
    expected_res = [service1, None]

    find_did_service_mock.side_effect = (x for x in expected_res)

    with pytest.raises(InvalidDIDDocError) as excinfo:
        await resolve_did_services_chain(resolvers_config_mock, did1)

    assert (
        f"mediator '{service1.service_endpoint}' "
        "service doc not found"
    ) in str(excinfo.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "did_recursion, exc_t",
    [
        pytest.param(True, NotImplementedError, id="expected"),
        pytest.param(False, InvalidDIDDocError, id="unexpected")
    ]
)
async def test_resolve_did_services_chain__did_endpoint_recursion(
    did_recursion,
    exc_t,
    resolvers_config_mock,
    did1,
    did2,
    find_did_service_mock,
):
    service1 = DIDCommService("", did1, [""], [""])
    service2 = DIDCommService("", did2, [""], [""])
    service3 = DIDCommService("", "https://some.domain", [""], [""])
    expected_res = [service1, service2, service3]

    find_did_service_mock.side_effect = (x for x in expected_res)

    with pytest.raises(exc_t) as excinfo:
        await resolve_did_services_chain(
            resolvers_config_mock, did1, did_recursion=did_recursion
        )
    assert (
        f"mediator '{service1.service_endpoint}' "
        "defines alternative endpoint"
    ) in str(excinfo.value)
