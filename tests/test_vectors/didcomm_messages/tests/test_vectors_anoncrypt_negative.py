from didcomm.vendor.authlib.common.encoding import json_dumps

from didcomm.errors import MalformedMessageError
from tests.test_vectors.common import TTestVectorNegative
from tests.test_vectors.didcomm_messages.spec.spec_test_vectors_anon_encrypted import (
    TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1,
)
from tests.test_vectors.didcomm_messages.tests.common import update, update_protected

INVALID_MESSAGES = [
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1, "protected", "invalid"),
    update_protected(TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1, "apv", "invalid"),
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1, "iv", "invalid"),
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1, "ciphertext", "invalid"),
    update(TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON_XC20P_1, "tag", "invalid"),
    # TODO: add more
]

INVALID_ANONCRYPT_TEST_VECTORS = [
    TTestVectorNegative(value, MalformedMessageError) for value in INVALID_MESSAGES
]

ANONCRYPT_MESSAGE_P256_XC20P_EPK_WRONG_POINT = json_dumps(
    {
        "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJYQzIwUCIsImFwdSI6bnVsbCwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IkZSQW1UQmljUFZJXy1aRnF2WEJwNzZhV2pZM0gzYlpGZlhocHRUNm1ETnciLCJ5IjoiLXZ0LTFIaHRvVjBwN2xrbGIxTnRvMWRhU0lqQnV3cVZzbGIwcC1uOWRrdyJ9fQ==",
        "recipients": [
            {
                "header": {"kid": "did:example:bob#key-p256-1"},
                "encrypted_key": "scQxV9YQ4mQrUHgl6yAnBFDXNZAiIs_15bmoErUmoYm0HtuRclPoQg",
            },
            {
                "header": {"kid": "did:example:bob#key-p256-2"},
                "encrypted_key": "CqZ-HDH2j0NC-eoUueNLKyAuMQXjQyw8bJHYM2f-lxJVm3eXCdmm2g",
            },
        ],
        "iv": "Vg1uyuQKrU6Kw8OJK38WCpYFxW0suAP9",
        "ciphertext": "2nIm3xQcFR3HXbUPF1HS_D92OGVDvL0nIi6O5ol5tnMIa09NxJtbVAYIG7ZrkT9314PqXn_Rq77hgGE6FAOgO7aNYLyUJh0JCC_i2p_XOWuk20BYyBsmmRvVpg0DY3I1Lb-Vg1pT9pEy09gsMSLhbfqk0_TFJB1rcqzR8W0YZB5mX_53nMRf1ZatDEg4rDogSekWEGTBnlTNRua8-zoI4573SfgJ-ONt7Z_KbGO-sdRkmqXhfYNcbUyoMF9JSa-kraVuWHZP9hTz8-7R020EXfb4jodMWVOMMAiJYk1Cd7tetHXpLPdtuokaapofmtL_SNftAX2CB6ULf0axrHUNtvUyjAPvpgvSuvQuMrDlaXn16MQJ_q55",
        "tag": "etLTQvKsTvF629fykLiUDg",
    }
)
