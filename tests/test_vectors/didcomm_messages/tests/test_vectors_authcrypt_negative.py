from didcomm.errors import MalformedMessageError
from tests.test_vectors.common import TestVectorNegative

INVALID_MESSAGES = [
    # TODO
]

INVALID_AUTHCRYPT_TEST_VECTORS = [
    TestVectorNegative(value, MalformedMessageError) for value in INVALID_MESSAGES
]
