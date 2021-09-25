from didcomm.errors import MalformedMessageError
from tests.test_vectors.common import TTestVectorNegative
from tests.test_vectors.didcomm_messages.spec.spec_test_vectors_auth_encrypted import (
    TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_X25519,
)
from tests.test_vectors.didcomm_messages.tests.common import update, update_protected

INVALID_MESSAGES = [
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_X25519, "protected", "invalid"),
    update_protected(TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_X25519, "apv", "invalid"),
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_X25519, "iv", "invalid"),
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_X25519, "ciphertext", "invalid"),
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_X25519, "tag", "invalid"),
    # TODO: add more
]

INVALID_AUTHCRYPT_TEST_VECTORS = [
    TTestVectorNegative(value, MalformedMessageError) for value in INVALID_MESSAGES
]
