import copy

from didcomm.errors import DIDCommValueError
from didcomm import (
    Message,
    Attachment,
    AttachmentDataBase64,
    AttachmentDataLinks,
    AttachmentDataJson,
    FromPrior,
)
from tests.test_vectors.common import (
    ALICE_DID,
    BOB_DID,
    CHARLIE_DID,
    TTestVectorNegative,
)

TEST_MESSAGE = Message(
    id="1234567890",
    thid="1234567890",
    type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
    frm=ALICE_DID,
    to=[BOB_DID],
    created_time=1516269022,
    expires_time=1516385931,
    body={"messagespecificattribute": "and its value"},
)

TEST_ATTACHMENT = Attachment(
    id="123",
    data=AttachmentDataBase64(base64="qwerty"),
    description="abc",
    filename="abc",
    media_type="abc",
    format="abc",
    lastmod_time=123,
    byte_count=1234,
)

TEST_ATTACHMENT_MINIMAL = Attachment(
    id="123",
    data=AttachmentDataBase64(base64="qwerty"),
)

TEST_FROM_PRIOR = FromPrior(
    iss="did:example:charlie",
    sub="did:example:alice",
    aud="123",
    exp=1234,
    nbf=12345,
    iat=123456,
    jti="dfg",
)

TEST_FROM_PRIOR_MINIMAL = FromPrior(
    iss="did:example:charlie",
    sub="did:example:alice",
)


TEST_MESSAGE_FROM_PRIOR_MINIMAL = Message(
    id="1234567890",
    type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
    frm=ALICE_DID,
    to=[BOB_DID],
    created_time=1516269022,
    expires_time=1516385931,
    from_prior=FromPrior(
        iss=CHARLIE_DID,
        sub=ALICE_DID,
    ),
    body={"messagespecificattribute": "and its value"},
)


TEST_MESSAGE_FROM_PRIOR = Message(
    id="1234567890",
    type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
    frm=ALICE_DID,
    to=[BOB_DID],
    created_time=1516269022,
    expires_time=1516385931,
    from_prior=FromPrior(
        iss=CHARLIE_DID,
        sub=ALICE_DID,
        aud="123",
        exp=1234,
        nbf=12345,
        iat=123456,
        jti="dfg",
    ),
    body={"messagespecificattribute": "and its value"},
)


TEST_MESSAGE_INVALID_FROM_PRIOR_EQUAL_ISS_AND_SUB = Message(
    id="1234567890",
    type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
    frm=ALICE_DID,
    to=[BOB_DID],
    created_time=1516269022,
    expires_time=1516385931,
    from_prior=FromPrior(
        iss=ALICE_DID,
        sub=ALICE_DID,
    ),
    body={"messagespecificattribute": "and its value"},
)


TEST_MESSAGE_MISMATCHED_FROM_PRIOR_SUB = Message(
    id="1234567890",
    type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
    frm=ALICE_DID,
    to=[BOB_DID],
    created_time=1516269022,
    expires_time=1516385931,
    from_prior=FromPrior(
        iss=CHARLIE_DID,
        sub="did:example:dave",
    ),
    body={"messagespecificattribute": "and its value"},
)


INVALID_FROM_PRIOR_MESSAGES = [
    TEST_MESSAGE_INVALID_FROM_PRIOR_EQUAL_ISS_AND_SUB,
    TEST_MESSAGE_MISMATCHED_FROM_PRIOR_SUB,
]


INVALID_FROM_PRIOR_TEST_VECTORS = [
    TTestVectorNegative(msg, DIDCommValueError) for msg in INVALID_FROM_PRIOR_MESSAGES
]


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


def ack_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.please_ack = ["a_msg"]
    msg.ack = ["another_msg"]
    return msg
