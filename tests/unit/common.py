from authlib.common.encoding import json_loads

from didcomm.core.utils import parse_base64url_encoded_json
from didcomm.unpack import unpack
from tests.test_vectors.test_vectors_common import TestVector, TEST_MESSAGE


def decode_and_remove_signatures(jws: str) -> dict:
    jws = json_loads(jws)
    jws["payload"] = parse_base64url_encoded_json(jws["payload"])
    for s in jws["signatures"]:
        s["protected"] = parse_base64url_encoded_json(s["protected"])
        del s["signature"]
    return jws


async def unpack_test_vector(test_vector: TestVector, resolvers_config):
    unpack_result = await unpack(resolvers_config, test_vector.value)
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_result.metadata == test_vector.metadata
