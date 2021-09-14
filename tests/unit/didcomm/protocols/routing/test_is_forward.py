import pytest

from didcomm.protocols.routing import forward


@pytest.mark.parametrize(
    "msg, method",
    [
        ({}, 'from_dict'),
        ('123', 'from_json'),
        (b'456', 'from_json')
    ], ids=['dict', 'str', 'bytes']
)
def test_is_forward__logic(mocker, msg, method):
    mock = mocker.patch.object(forward.ForwardMessage, method)
    forward.is_forward(msg)
    mock.assert_called_once_with(msg)
