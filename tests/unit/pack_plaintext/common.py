import copy

from didcomm.message import (
    Attachment,
    AttachmentDataJson,
    AttachmentDataBase64,
    AttachmentDataLinks,
    Message,
)
from tests.test_vectors.common import TEST_MESSAGE


def create_minimal_msg():
    return Message(
        id="1234567890",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        body={},
    )
