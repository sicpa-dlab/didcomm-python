import pytest
from authlib.common.encoding import json_dumps

from didcomm.errors import MalformedMessageError
from didcomm.unpack import unpack
from tests.test_vectors.common import TTestVectorNegative

PACKED_MESSAGE_INVALID_FROM_PRIOR = json_dumps(
    {
        "id": "1234567890",
        "typ": "application/didcomm-plain+json",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "from": "did:example:alice",
        "to": ["did:example:bob"],
        "created_time": 1516269022,
        "expires_time": 1516385931,
        "from_prior": "invalid",
        "body": {"messagespecificattribute": "and its value"},
    }
)


PACKED_MESSAGE_INVALID_FROM_PRIOR_SIGNATURE = json_dumps(
    {
        "id": "1234567890",
        "typ": "application/didcomm-plain+json",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "from": "did:example:alice",
        "to": ["did:example:bob"],
        "created_time": 1516269022,
        "expires_time": 1516385931,
        "from_prior": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOmNoYXJsaWUja2V5LTEifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpjaGFybGllIiwic3ViIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJhdWQiOiIxMjMiLCJleHAiOjEyMzQsIm5iZiI6MTIzNDUsImlhdCI6MTIzNDU2LCJqdGkiOiJkZmcifQ.9F1o6duu_lC6LTZN-RN3R6uUl_p63ma30i8nNu2xoCmOc-lE9G1z1-iZ2jZ81kFmq5aOMyhcVXat6TOGJdcVD",
        "body": {"messagespecificattribute": "and its value"},
    }
)


INVALID_TEST_VECTORS = [
    TTestVectorNegative(PACKED_MESSAGE_INVALID_FROM_PRIOR, MalformedMessageError),
    TTestVectorNegative(
        PACKED_MESSAGE_INVALID_FROM_PRIOR_SIGNATURE, MalformedMessageError
    ),
]


@pytest.mark.parametrize("test_vector", INVALID_TEST_VECTORS)
@pytest.mark.asyncio
async def test_unpack_plaintext_with_invalid_from_prior(
    test_vector,
    resolvers_config_bob,
):
    with pytest.raises(test_vector.exc):
        await unpack(resolvers_config_bob, test_vector.value)
