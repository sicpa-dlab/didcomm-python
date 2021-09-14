from authlib.common.encoding import json_dumps

from didcomm.errors import MalformedMessageError
from tests.test_vectors.common import TTestVectorNegative

INVALID_MESSAGES = [
    json_dumps({}),
    json_dumps("aaa"),
    json_dumps(
        {
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "body": {},
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json-unknown",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
            "attachments": [{}],
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
            "attachments": [{"id": "23"}],
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
            "attachments": [{"id": "23", "data": {}}],
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
            "attachments": [{"id": "23", "data": {"links": ["231", "212"]}}],
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
            "attachments": "131",
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
            "attachments": [2131],
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
            "attachments": [{"id": 2}],
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
            "attachments": [{"id": "1", "data": None}],
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
            "attachments": [{"id": "1", "data": "None"}],
        }
    ),
    json_dumps(
        {
            "id": "1234567890",
            "typ": "application/didcomm-plain+json",
            "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
            "body": {},
            "attachments": [{"id": "1", "data": "None"}],
        }
    ),
    # TODO: add more
]

INVALID_PLAINTEXT_TEST_VECTORS = [
    TTestVectorNegative(value, MalformedMessageError) for value in INVALID_MESSAGES
]
