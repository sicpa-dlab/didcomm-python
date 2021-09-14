import pytest
from unittest.mock import AsyncMock

from didcomm.common.types import DID, DID_URL
from didcomm.common.resolvers import ResolversConfig
from didcomm.protocols.routing.forward import (
    ForwardMessage
)

from .helper import gen_fwd_msg


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
def fwd_msg() -> ForwardMessage:
    return gen_fwd_msg()


@pytest.fixture
def resolvers_config_mock(mocker) -> ResolversConfig:
    secrets_resolver = mocker.Mock()
    did_resolver = mocker.Mock()
    did_resolver.resolve = AsyncMock()
    return ResolversConfig(secrets_resolver, did_resolver)
