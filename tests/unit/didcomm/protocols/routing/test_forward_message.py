import pytest
import attr
from typing import Callable

from didcomm.errors import DIDCommValueError, MalformedMessageError
from didcomm.core import converters
from didcomm.core.types import DIDCOMM_ORG_DOMAIN, DIDCommFields
from didcomm.protocols.routing.forward import (
    ForwardBody,
    ForwardMessage,
    ROUTING_PROTOCOL_NAME,
    ROUTING_PROTOCOL_VER_CURRENT,
    ROUTING_PROTOCOL_MSG_TYPES,
)

from .helper import diff_type_objects, gen_fwd_msg, gen_fwd_msg_dict


# TODO add tests for ForwardBody
# def test_forward_body__(m_id):
#     pass


# TODO test that Callable[[], <not-str>] is also bad
@pytest.mark.parametrize(
    "m_id",
    [o for o in diff_type_objects if not isinstance(o, (str, Callable))],
    ids=lambda x: type(x).__name__,
)
def test_forward_message__id_bad(m_id, fwd_msg):
    with pytest.raises(DIDCommValueError):
        attr.evolve(fwd_msg, **dict(id=m_id))


@pytest.mark.parametrize(
    "m_id, m_id_expected",
    [
        pytest.param("123", "123", id="str"),
        pytest.param(lambda: "345", "345", id="function"),
        pytest.param(None, None, id="default"),
    ],
)
def test_forward_message__id_good(m_id, m_id_expected, mocker, fwd_msg):
    if m_id is None:
        # XXX mocks in-place of imports doesn't work for attrs calsses
        #     by some reason
        spy = mocker.spy(converters, "didcomm_id_generator_default")
        msg = gen_fwd_msg()
        assert spy.call_count == 1
        assert msg.id == spy.spy_return
    else:
        assert attr.evolve(fwd_msg, **dict(id=m_id)).id == m_id_expected


def _build_mturi(
    scheme="https",
    domain=DIDCOMM_ORG_DOMAIN,
    prot=ROUTING_PROTOCOL_NAME,
    ver=ROUTING_PROTOCOL_VER_CURRENT,
    msg_t=ROUTING_PROTOCOL_MSG_TYPES.FORWARD.value,
):
    return f"{scheme}://{domain}/{prot}/{ver}/{msg_t}"


# TODO cover exception messages as well
@pytest.mark.parametrize(
    "msg_t, exc_t",
    [
        pytest.param(123, DIDCommValueError, id="int"),
        pytest.param(_build_mturi(scheme="tcp"), DIDCommValueError, id="scheme"),
        pytest.param(
            _build_mturi(domain="somedomain.org"), DIDCommValueError, id="domain"
        ),
        pytest.param(
            _build_mturi(prot="someprotocol"), DIDCommValueError, id="protocol"
        ),
        pytest.param(_build_mturi(ver="3.0"), DIDCommValueError, id="too_old_version"),
        pytest.param(_build_mturi(ver="1.9"), DIDCommValueError, id="too_new_version"),
        pytest.param(_build_mturi(msg_t="somemsg"), DIDCommValueError, id="message_t"),
    ],
)
def test_forward_message__type_bad(msg_t, exc_t, fwd_msg):
    with pytest.raises(exc_t):
        attr.evolve(fwd_msg, **dict(type=msg_t))


@pytest.mark.parametrize("msg_ver", ["2.0", "2.0.1", "2.7.9"], ids=lambda x: f"v{x}")
def test_forward_message__type_good(msg_ver, fwd_msg):
    msg_t = _build_mturi(ver=msg_ver)
    assert attr.evolve(fwd_msg, **dict(type=msg_t)).type == msg_t


@pytest.mark.parametrize(
    "msg",
    [
        pytest.param(gen_fwd_msg_dict(remove=[DIDCommFields.ID]), id="no_id"),
        pytest.param(gen_fwd_msg_dict(remove=[DIDCommFields.TYPE]), id="no_type"),
        pytest.param(gen_fwd_msg_dict(remove=[DIDCommFields.TYP]), id="no_typ"),
        pytest.param(gen_fwd_msg_dict(remove=[DIDCommFields.BODY]), id="no_body"),
        # TODO the cases above better to test in scope of GenericMessage
        pytest.param(gen_fwd_msg_dict(update={DIDCommFields.BODY: {}}), id="no_next"),
        pytest.param(
            gen_fwd_msg_dict(remove=[DIDCommFields.ATTACHMENTS]), id="no_attach"
        ),
        pytest.param(
            gen_fwd_msg_dict(update={DIDCommFields.ATTACHMENTS: []}), id="empty_attach"
        ),
    ],
)
def test_forward_message_from_dict__bad_msg(msg):
    with pytest.raises(MalformedMessageError):
        assert not ForwardMessage.from_dict(msg)


def test_forward_message__body_from_dict(did):
    body = {DIDCommFields.NEXT: did}
    fwd_body = ForwardMessage._body_from_dict(body)
    assert isinstance(fwd_body, ForwardBody)
    assert fwd_body.next == body["next"]
