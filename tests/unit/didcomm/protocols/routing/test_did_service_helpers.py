import pytest

from didcomm.errors import DIDDocNotResolvedError, InvalidDIDDocError
from didcomm.protocols.routing import forward  # for patch.object mocks
from didcomm.protocols.routing.forward import (
    find_did_service,
    resolve_did_services_chain,
    PROFILE_DIDCOMM_AIP2_ENV_RFC587,
    PROFILE_DIDCOMM_AIP2_ENV_RFC19,
    PROFILE_DIDCOMM_AIP1,
    PROFILE_DIDCOMM_V2,
)
from tests import mock_module
from tests.unit.conftest import build_did_doc, build_didcomm_service


# ===============
# find_did_service
# ===============


@pytest.mark.asyncio
async def test_find_did_service__no_diddoc(resolvers_config_mock, did_doc):
    resolve_mock = resolvers_config_mock.did_resolver.resolve
    resolve_mock.return_value = None

    with pytest.raises(DIDDocNotResolvedError):
        await find_did_service(resolvers_config_mock, did_doc.id)

    resolve_mock.assert_awaited_once_with(did_doc.id)


@pytest.mark.asyncio
async def test_find_did_service__no_service_with_v2_profile(resolvers_config_mock):
    resolve_mock = resolvers_config_mock.did_resolver.resolve

    service1 = build_didcomm_service(
        accept=[PROFILE_DIDCOMM_AIP2_ENV_RFC587, PROFILE_DIDCOMM_AIP2_ENV_RFC19],
    )

    did_doc = build_did_doc(service=[service1])
    resolve_mock.return_value = did_doc

    res = await find_did_service(resolvers_config_mock, did_doc.id)
    assert res is None


@pytest.mark.asyncio
async def test_find_did_service__first_service_with_v2_profile(resolvers_config_mock):
    resolve_mock = resolvers_config_mock.did_resolver.resolve

    service1 = build_didcomm_service(
        accept=[PROFILE_DIDCOMM_AIP2_ENV_RFC587, PROFILE_DIDCOMM_AIP2_ENV_RFC19],
    )

    service2 = build_didcomm_service(
        accept=[PROFILE_DIDCOMM_AIP1, PROFILE_DIDCOMM_V2],
    )

    service3 = build_didcomm_service(
        accept=[PROFILE_DIDCOMM_V2, PROFILE_DIDCOMM_AIP2_ENV_RFC19],
    )

    did_doc = build_did_doc(service=[service1, service2, service3])
    resolve_mock.return_value = did_doc

    res = await find_did_service(resolvers_config_mock, did_doc.id)
    assert res == service2


@pytest.mark.asyncio
async def test_find_did_service__no_service_id(resolvers_config_mock, did_doc):
    resolve_mock = resolvers_config_mock.did_resolver.resolve
    resolve_mock.return_value = did_doc

    with pytest.raises(InvalidDIDDocError):
        await find_did_service(resolvers_config_mock, did_doc.id, service_id="did2")


@pytest.mark.asyncio
async def test_find_did_service__by_service_id(resolvers_config_mock):
    resolve_mock = resolvers_config_mock.did_resolver.resolve

    service1 = build_didcomm_service(
        id="did:example:1#1",
        accept=[PROFILE_DIDCOMM_V2],
    )

    service2 = build_didcomm_service(
        id="did:example:2#2",
        accept=[PROFILE_DIDCOMM_V2],
    )

    did_doc = build_did_doc(service=[service1, service2])
    resolve_mock.return_value = did_doc

    res = await find_did_service(
        resolvers_config_mock, did_doc.id, service_id=service2.id
    )
    assert res == service2


@pytest.mark.asyncio
async def test_find_did_service__by_service_id_no_v2_profile(resolvers_config_mock):
    resolve_mock = resolvers_config_mock.did_resolver.resolve

    service1 = build_didcomm_service(id="did:example:1#1", accept=[PROFILE_DIDCOMM_V2])
    service2 = build_didcomm_service(
        id="did:example:2#2", accept=[PROFILE_DIDCOMM_AIP1]
    )

    did_doc = build_did_doc(service=[service1, service2])
    resolve_mock.return_value = did_doc

    with pytest.raises(InvalidDIDDocError):
        await find_did_service(
            resolvers_config_mock, did_doc.id, service_id=service2.id
        )


# ==========================
# resolve_did_services_chain
# ==========================


@pytest.fixture
def find_did_service_mock(mocker) -> mock_module.AsyncMock:
    return mocker.patch.object(forward, "find_did_service")


@pytest.mark.asyncio
async def test_resolve_did_services_chain__no_service(
    resolvers_config_mock, did_doc, find_did_service_mock
):
    find_did_service_mock.return_value = None
    res = await resolve_did_services_chain(resolvers_config_mock, did_doc.id)
    assert res == []


@pytest.mark.asyncio
async def test_resolve_did_services_chain__uri_as_endpoint(
    resolvers_config_mock, did_doc, find_did_service_mock
):
    didcomm_service = build_didcomm_service(service_endpoint="https://some.domain")
    find_did_service_mock.return_value = didcomm_service
    res = await resolve_did_services_chain(resolvers_config_mock, did_doc.id)
    assert len(res) == 1
    assert res[0] is didcomm_service


@pytest.mark.asyncio
async def test_resolve_did_services_chain__did_as_endpoint(
    resolvers_config_mock, did1, find_did_service_mock
):
    service1 = build_didcomm_service(service_endpoint=did1 + "#1")
    service2 = build_didcomm_service(service_endpoint="https://some.domain")
    find_did_service_return = [service1, service2]
    expected_res = list(reversed(find_did_service_return))

    find_did_service_mock.side_effect = (x for x in find_did_service_return)

    res = await resolve_did_services_chain(resolvers_config_mock, did1)
    assert res == expected_res


@pytest.mark.asyncio
async def test_resolve_did_services_chain__no_mediator_did_service(
    resolvers_config_mock, did1, did2, find_did_service_mock
):
    service1 = build_didcomm_service(service_endpoint=did1 + "#1")
    find_did_service_return = [service1, None]

    find_did_service_mock.side_effect = (x for x in find_did_service_return)

    with pytest.raises(InvalidDIDDocError) as excinfo:
        await resolve_did_services_chain(resolvers_config_mock, did1)

    assert f"mediator '{service1.service_endpoint}' " "service doc not found" in str(
        excinfo.value
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "did_recursion, exc_t",
    [
        pytest.param(True, NotImplementedError, id="expected"),
        pytest.param(False, InvalidDIDDocError, id="unexpected"),
    ],
)
async def test_resolve_did_services_chain__did_endpoint_recursion(
    did_recursion,
    exc_t,
    resolvers_config_mock,
    did1,
    did2,
    find_did_service_mock,
):
    service1 = build_didcomm_service(service_endpoint=did1 + "#1")
    service2 = build_didcomm_service(service_endpoint=did2 + "#1")
    service3 = build_didcomm_service(service_endpoint="https://some.domain")

    find_did_service_mock.side_effect = (x for x in [service1, service2, service3])

    with pytest.raises(exc_t) as excinfo:
        await resolve_did_services_chain(
            resolvers_config_mock, did1, did_recursion=did_recursion
        )
    assert (
        f"mediator '{service1.service_endpoint}' " "defines alternative endpoint"
    ) in str(excinfo.value)
