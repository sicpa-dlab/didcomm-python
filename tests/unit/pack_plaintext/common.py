from didcomm.message import (
    Message,
)


def create_minimal_msg():
    return Message(
        id="1234567890",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        body={},
    )
