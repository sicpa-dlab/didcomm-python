import copy

from authlib.common.encoding import json_loads

from didcomm.core.utils import parse_base64url_encoded_json
from didcomm.unpack import unpack, Metadata
from tests.test_vectors.common import TestVector, TEST_MESSAGE


def decode_and_remove_jws_signatures(jws: str) -> dict:
    jws = json_loads(jws)
    jws["payload"] = parse_base64url_encoded_json(jws["payload"])
    for s in jws["signatures"]:
        s["protected"] = parse_base64url_encoded_json(s["protected"])
        del s["signature"]
    return jws


def decode_jwe_headers(jwe: str) -> dict:
    jwe = json_loads(jwe)
    protected = parse_base64url_encoded_json(jwe["protected"])
    del protected["epk"]
    recipients = jwe["recipients"]
    for r in recipients:
        del r["encrypted_key"]
    return {"protected": protected, "recipients": recipients}


def remove_signed_msg(metadata: Metadata) -> Metadata:
    metadata = copy.deepcopy(metadata)
    metadata.signed_message = None
    return metadata


async def check_unpack_test_vector(test_vector: TestVector, resolvers_config):
    unpack_result = await unpack(resolvers_config, test_vector.value)
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_result.metadata == test_vector.metadata
