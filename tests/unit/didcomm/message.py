import pytest
import attr

from didcomm.core import converters
from didcomm.message import GenericMessage


@pytest.mark.parametrize(
    "m_id, m_id_expected",
    [
        pytest.param("123", "123", id="str"),
        pytest.param(lambda: "345", "345", id="function"),
        pytest.param(None, None, id="default"),
    ],
)
def test_forward_message__id_good(m_id, m_id_expected, mocker):
    if m_id is None:
        # XXX mocks in-place of imports doesn't work for attrs calsses
        #     by some reason
        spy = mocker.spy(converters, "didcomm_id_generator_default")
        msg = GenericMessage(type="test_type", body="test_body")
        assert spy.call_count == 1
        assert msg.id == spy.spy_return
    else:
        msg = GenericMessage(type="test_type", body="test_body")
        assert attr.evolve(msg, **dict(id=m_id)).id == m_id_expected
