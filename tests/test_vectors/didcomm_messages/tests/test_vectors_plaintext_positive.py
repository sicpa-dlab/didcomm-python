from didcomm.vendor.authlib.common.encoding import json_dumps

from didcomm.unpack import Metadata

PLAINTEXT_EXPECTED_METADATA = Metadata(
    encrypted=False,
    authenticated=False,
    non_repudiation=False,
    anonymous_sender=False,
)

TEST_PLAINTEXT_DIDCOMM_MESSAGE_MINIMAL = json_dumps(
    {
        "id": "1234567890",
        "typ": "application/didcomm-plain+json",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "body": {},
    }
)

TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE = json_dumps(
    {
        "id": "1234567890",
        "typ": "application/didcomm-plain+json",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "from": "did:example:alice",
        "to": ["did:example:bob"],
        "created_time": 1516269022,
        "expires_time": 1516385931,
        "body": {"messagespecificattribute": "and its value"},
    }
)

TEST_PLAINTEXT_ATTACHMENT_BASE64 = json_dumps(
    {
        "id": "1234567890",
        "typ": "application/didcomm-plain+json",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "from": "did:example:alice",
        "to": ["did:example:bob"],
        "created_time": 1516269022,
        "expires_time": 1516385931,
        "body": {"messagespecificattribute": "and its value"},
        "attachments": [{"id": "23", "data": {"base64": "qwerty"}}],
    }
)

TEST_PLAINTEXT_ATTACHMENT_LINKS = json_dumps(
    {
        "id": "1234567890",
        "typ": "application/didcomm-plain+json",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "from": "did:example:alice",
        "to": ["did:example:bob"],
        "created_time": 1516269022,
        "expires_time": 1516385931,
        "body": {"messagespecificattribute": "and its value"},
        "attachments": [
            {"id": "23", "data": {"links": ["1", "2", "3"], "hash": "qwerty"}}
        ],
    }
)

TEST_PLAINTEXT_ATTACHMENT_JSON = json_dumps(
    {
        "id": "1234567890",
        "typ": "application/didcomm-plain+json",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "from": "did:example:alice",
        "to": ["did:example:bob"],
        "created_time": 1516269022,
        "expires_time": 1516385931,
        "body": {"messagespecificattribute": "and its value"},
        "attachments": [
            {"id": "23", "data": {"json": {"foo": "bar", "links": [2, 3]}}}
        ],
    }
)

TEST_PLAINTEXT_ATTACHMENT_MULTI_1 = json_dumps(
    {
        "id": "1234567890",
        "typ": "application/didcomm-plain+json",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "from": "did:example:alice",
        "to": ["did:example:bob"],
        "created_time": 1516269022,
        "expires_time": 1516385931,
        "body": {"messagespecificattribute": "and its value"},
        "attachments": [
            {"id": "23", "data": {"json": {"foo": "bar", "links": [2, 3]}}},
            {"id": "24", "data": {"base64": "qwerty"}},
            {"id": "25", "data": {"links": ["1", "2", "3"], "hash": "qwerty"}},
        ],
    }
)
TEST_PLAINTEXT_ATTACHMENT_MULTI_2 = json_dumps(
    {
        "id": "1234567890",
        "typ": "application/didcomm-plain+json",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "from": "did:example:alice",
        "to": ["did:example:bob"],
        "created_time": 1516269022,
        "expires_time": 1516385931,
        "body": {"messagespecificattribute": "and its value"},
        "attachments": [
            {"id": "23", "data": {"links": ["1", "2", "3"], "hash": "qwerty"}},
            {"id": "24", "data": {"base64": "qwerty"}},
            {"id": "25", "data": {"links": ["1", "2", "3", "4"], "hash": "qwerty2"}},
        ],
    }
)
