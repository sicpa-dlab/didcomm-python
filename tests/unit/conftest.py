from string import ascii_letters
import random

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


def build_didcomm_service(
    id=None,
    service_endpoint="https://example.com/endpoint",
    routing_keys=None,
    recipient_keys=None,
    accept=None,
) -> DIDCommService:
    return DIDCommService(
        # id needs to be unique, so we generate 8 letters random fragment
        id=id
        or "did:example:some_did#"
        + "".join(random.choice(ascii_letters) for i in range(8)),
        service_endpoint=service_endpoint,
        routing_keys=routing_keys or [],
        recipient_keys=recipient_keys or [],
        accept=accept or [],
    )


@pytest.fixture
def didcomm_service():
    return build_didcomm_service(
        id="did:example:some_did#service",
        service_endpoint="https://example.com/endpoint",
        routing_keys=[
            "did:example:some_did#key-1",
            "did:example:some_did#key-2",
            "did:example:some_did#key-3",
        ],
        accept=["didcomm/v2"],
    )


@pytest.fixture
def didcomm_service1(didcomm_service):
    return didcomm_service


@pytest.fixture
def didcomm_service2(didcomm_service1):
    return build_didcomm_service(
        id=didcomm_service1.id.replace("1", "2"),
        service_endpoint=didcomm_service1.service_endpoint.replace("1", "2"),
        routing_keys=[
            "did:example:some_did#key-4",
            "did:example:some_did#key-5",
            "did:example:some_did#key-6",
        ],
        accept=[""],
    )


@pytest.fixture
def didcomm_service3(didcomm_service1):
    return build_didcomm_service(
        id=didcomm_service1.id.replace("1", "3"),
        service_endpoint=didcomm_service1.service_endpoint.replace("1", "3"),
        routing_keys=[
            "did:example:some_did#key-7",
            "did:example:some_did#key-8",
            "did:example:some_did#key-9",
        ],
        accept=[""],
    )


def build_did_doc(
    did="did:example:1",
    key_agreement=None,
    authentication=None,
    verification_method=None,
    service=None,
) -> DIDDoc:
    return DIDDoc(
        id=did,
        key_agreement=key_agreement or [],
        authentication=authentication or [],
        verification_method=verification_method or [],
        service=service or [],
    )


@pytest.fixture
def did_doc(did) -> DIDDoc:
    return build_did_doc(did)


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
