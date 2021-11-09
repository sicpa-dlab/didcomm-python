import pytest
from authlib.common.encoding import json_dumps

from didcomm.core.serialization import json_str_to_dict
from didcomm.unpack import unpack
from tests.test_vectors.didcomm_messages.messages import TEST_MESSAGE_FROM_PRIOR

PACKED_MESSAGE = json_dumps(
    {
        "id": "1234567890",
        "typ": "application/didcomm-plain+json",
        "type": "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        "from": "did:example:alice",
        "to": ["did:example:bob"],
        "created_time": 1516269022,
        "expires_time": 1516385931,
        "from_prior": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOmNoYXJsaWUja2V5LTEifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpjaGFybGllIiwic3ViIjoiZGlkOmV4YW1wbGU6YWxpY2UiLCJhdWQiOiIxMjMiLCJleHAiOjEyMzQsIm5iZiI6MTIzNDUsImlhdCI6MTIzNDU2LCJqdGkiOiJkZmcifQ.xIdfOLizPZMOZPAqMatEuBk0OrVge6jN1nxYlWUISz0XUXdW6TbwDbMgTinx2CLxtxev_gqEuZw5c98E3-eaAQ",
        "body": {"messagespecificattribute": "and its value"},
    }
)


@pytest.mark.asyncio
async def test_unpack_plaintext_with_from_prior(
    resolvers_config_bob,
):
    unpack_result = await unpack(resolvers_config_bob, PACKED_MESSAGE)

    assert unpack_result.message == TEST_MESSAGE_FROM_PRIOR
    assert unpack_result.metadata.from_prior_issuer_kid == "did:example:charlie#key-1"
    assert (
        unpack_result.metadata.from_prior_jwt
        == json_str_to_dict(PACKED_MESSAGE)["from_prior"]
    )
