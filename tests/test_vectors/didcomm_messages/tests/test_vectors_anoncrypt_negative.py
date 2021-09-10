from didcomm.errors import MalformedMessageError
from tests.test_vectors.common import TestVectorNegative
from tests.test_vectors.didcomm_messages.spec.spec_test_vectors_anon_encrypted import (
    TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1,
)
from tests.test_vectors.didcomm_messages.tests.common import update

INVALID_MESSAGES = [
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1, "ciphertext", "invalid"),
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1, "protected", "invalid"),
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1, "tag", "invalid"),
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1, "iv", "invalid")
    # TODO: add more
]

INVALID_ANONCRYPT_TEST_VECTORS = [
    TestVectorNegative(value, MalformedMessageError) for value in INVALID_MESSAGES
]
