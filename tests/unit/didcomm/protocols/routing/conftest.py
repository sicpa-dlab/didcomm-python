import pytest

from didcomm.protocols.routing.forward import ForwardMessage

from .helper import gen_fwd_msg


@pytest.fixture
def fwd_msg() -> ForwardMessage:
    return gen_fwd_msg()
