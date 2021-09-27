import pytest

from didcomm.common.types import DID, DID_URL
from didcomm.did_doc.did_doc import DIDDoc, DIDCommService
from didcomm.pack_encrypted import (
    PackEncryptedConfig,
    PackEncryptedParameters,
)
from didcomm.common.resolvers import ResolversConfig

from tests import mock_module


# ==============
# unittest mocks
# ==============


@pytest.fixture
def did() -> DID:
    return "did:example:1"


@pytest.fixture
def did1(did) -> DID:
    return did


@pytest.fixture
def did2(did) -> DID:
    return did.replace("1", "2")


@pytest.fixture
def did3(did) -> DID:
    return did.replace("1", "3")


@pytest.fixture
def did_url(did) -> DID_URL:
    return "{did}#somekey1"


@pytest.fixture
def didcomm_service():
    return DIDCommService("id_1", "endp_1", ["1", "2", "3"], [""])


@pytest.fixture
def didcomm_service1(didcomm_service):
    return didcomm_service


@pytest.fixture
def didcomm_service2(didcomm_service1):
    return DIDCommService(
        didcomm_service1.id.replace("1", "2"),
        didcomm_service1.service_endpoint.replace("1", "2"),
        ["4", "5", "6"],
        [""],
    )


@pytest.fixture
def didcomm_service3(didcomm_service1):
    return DIDCommService(
        didcomm_service1.id.replace("1", "3"),
        didcomm_service1.service_endpoint.replace("1", "3"),
        ["7", "8", "9"],
        [""],
    )


@pytest.fixture
def did_doc(did) -> DIDDoc:
    return DIDDoc(did, [], [], [], [])


@pytest.fixture
def pack_config() -> PackEncryptedConfig:
    return PackEncryptedConfig()


@pytest.fixture
def pack_params() -> PackEncryptedParameters:
    return PackEncryptedParameters()


@pytest.fixture
def resolvers_config_mock(mocker) -> ResolversConfig:
    secrets_resolver = mocker.Mock()
    did_resolver = mocker.Mock()
    # NOTE AsyncMock from unittest.mock is availble only in python 3.8+
    #       - here we rely on PyPI backport https://pypi.org/project/mock/
    #       - the module supports python 3.6+
    did_resolver.resolve = mock_module.AsyncMock()
    return ResolversConfig(secrets_resolver, did_resolver)
