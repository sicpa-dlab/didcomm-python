import pytest

from didcomm.common.types import DID, DID_URL
from didcomm.common.resolvers import ResolversConfig
from didcomm.protocols.routing.forward import ForwardMessage

from tests import mock_module

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
    # NOTE AsyncMock from unittest.mock is availble only in python 3.8+
    #       - here we rely on PyPI backport https://pypi.org/project/mock/
    #       - the module supports python 3.6+
    did_resolver.resolve = mock_module.AsyncMock()
    return ResolversConfig(secrets_resolver, did_resolver)
