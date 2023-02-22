from authlib.common.encoding import json_dumps

from didcomm import Metadata

PLAINTEXT_EXPECTED_METADATA = Metadata(
    encrypted=False,
    authenticated=False,
    non_repudiation=False,
    anonymous_sender=False,
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
