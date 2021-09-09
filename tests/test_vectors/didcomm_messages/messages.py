import copy

from didcomm.message import (
    Message,
    Attachment,
    AttachmentDataBase64,
    AttachmentDataLinks,
    AttachmentDataJson,
)
from tests.test_vectors.common import ALICE_DID, BOB_DID

TEST_MESSAGE: Message = Message(
    id="1234567890",
    type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
    frm=ALICE_DID,
    to=[BOB_DID],
    created_time=1516269022,
    expires_time=1516385931,
    body={"messagespecificattribute": "and its value"},
)


def minimal_msg():
    return Message(
        id="1234567890",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        body={},
    )


def attachment_base64_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [Attachment(id="23", data=AttachmentDataBase64(base64="qwerty"))]
    return msg


def attachment_links_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [
        Attachment(
            id="23", data=AttachmentDataLinks(links=["1", "2", "3"], hash="qwerty")
        )
    ]
    return msg


def attachment_json_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [
        Attachment(
            id="23", data=AttachmentDataJson(json={"foo": "bar", "links": [2, 3]})
        )
    ]
    return msg


def attachment_multi_1_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [
        Attachment(
            id="23", data=AttachmentDataJson(json={"foo": "bar", "links": [2, 3]})
        ),
        Attachment(id="24", data=AttachmentDataBase64(base64="qwerty")),
        Attachment(
            id="25", data=AttachmentDataLinks(links=["1", "2", "3"], hash="qwerty")
        ),
    ]
    return msg


def attachment_multi_2_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [
        Attachment(
            id="23", data=AttachmentDataLinks(links=["1", "2", "3"], hash="qwerty")
        ),
        Attachment(id="24", data=AttachmentDataBase64(base64="qwerty")),
        Attachment(
            id="25",
            data=AttachmentDataLinks(links=["1", "2", "3", "4"], hash="qwerty2"),
        ),
    ]
    return msg
