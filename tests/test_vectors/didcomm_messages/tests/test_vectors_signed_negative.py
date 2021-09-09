from didcomm.errors import MalformedMessageError
from tests.test_vectors.common import TestVectorNegative
from tests.test_vectors.didcomm_messages.spec.spec_test_vectors_signed import (
    TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_1,
)
from tests.test_vectors.didcomm_messages.tests.common import update

INVALID_MESSAGES = [
    update(TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_1, "payload", "invalid"),
    # TODO: add more
]

INVALID_SIGNED_TEST_VECTORS = [
    TestVectorNegative(value, MalformedMessageError) for value in INVALID_MESSAGES
]
