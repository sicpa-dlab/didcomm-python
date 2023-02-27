import copy

from authlib.common.encoding import json_dumps

from didcomm.common.algorithms import SignAlg
from didcomm.unpack import Metadata
from tests.test_vectors.common import TTestVector

TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_1 = json_dumps(
    {
        "payload": "eyJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImJvZHkiOnsibWVzc2FnZXNwZWNpZmljYXR0cmlidXRlIjoiYW5kIGl0cyB2YWx1ZSJ9LCJpZCI6IjEyMzQ1Njc4OTAiLCJ0byI6WyJkaWQ6ZXhhbXBsZTpib2IiXSwiY3JlYXRlZF90aW1lIjoxNTE2MjY5MDIyLCJleHBpcmVzX3RpbWUiOjE1MTYzODU5MzEsInRoaWQiOiIxMjM0NTY3ODkwIiwiZnJvbSI6ImRpZDpleGFtcGxlOmFsaWNlIiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1wbGFpbitqc29uIn0",
        "signatures": [
            {
                "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                "signature": "D3aEM0sIPobl-qnJh7kF1Hol6Wz_CKmyqHfgwGbFKmjyWvUoXhCI09ZiE5qmJlyyPo_ubqEqWOiPYcroEjJ9Ag",
                "header": {"kid": "did:example:alice#key-1"},
            }
        ],
    }
)

TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_2 = json_dumps(
    {
        "payload": "eyJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImJvZHkiOnsibWVzc2FnZXNwZWNpZmljYXR0cmlidXRlIjoiYW5kIGl0cyB2YWx1ZSJ9LCJpZCI6IjEyMzQ1Njc4OTAiLCJ0byI6WyJkaWQ6ZXhhbXBsZTpib2IiXSwiY3JlYXRlZF90aW1lIjoxNTE2MjY5MDIyLCJleHBpcmVzX3RpbWUiOjE1MTYzODU5MzEsInRoaWQiOiIxMjM0NTY3ODkwIiwiZnJvbSI6ImRpZDpleGFtcGxlOmFsaWNlIiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1wbGFpbitqc29uIn0",
        "signatures": [
            {
                "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
                "signature": "YktGGyR1i23DGdMz0_yhrb5o4zLKja3VT-qKMFD2VhIX2Vb12SkbD2kREc6HZE-NcIBXmpTGu1P-HtWRp-Ys0g",
                "header": {"kid": "did:example:alice#key-2"},
            }
        ],
    }
)

TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_3 = json_dumps(
    {
        "payload": "eyJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImJvZHkiOnsibWVzc2FnZXNwZWNpZmljYXR0cmlidXRlIjoiYW5kIGl0cyB2YWx1ZSJ9LCJpZCI6IjEyMzQ1Njc4OTAiLCJ0byI6WyJkaWQ6ZXhhbXBsZTpib2IiXSwiY3JlYXRlZF90aW1lIjoxNTE2MjY5MDIyLCJleHBpcmVzX3RpbWUiOjE1MTYzODU5MzEsInRoaWQiOiIxMjM0NTY3ODkwIiwiZnJvbSI6ImRpZDpleGFtcGxlOmFsaWNlIiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1wbGFpbitqc29uIn0",
        "signatures": [
            {
                "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
                "signature": "mYLZAUz97lodaWbwED6IvBf9_8Zj41-dM6r_3gTE9AkVZI3AJlz-agDBNSmNHd3CjRKW1KNS10pND57123b9aA",
                "header": {"kid": "did:example:alice#key-3"},
            }
        ],
    }
)

TEST_SIGNED_DIDCOMM_MESSAGE = [
    TTestVector(
        TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_1,
        Metadata(
            encrypted=False,
            non_repudiation=True,
            authenticated=True,
            anonymous_sender=False,
            sign_from="did:example:alice#key-1",
            sign_alg=SignAlg.ED25519,
            signed_message=copy.deepcopy(TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_1),
        ),
    ),
    TTestVector(
        TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_2,
        Metadata(
            encrypted=False,
            non_repudiation=True,
            authenticated=True,
            anonymous_sender=False,
            sign_from="did:example:alice#key-2",
            sign_alg=SignAlg.ES256,
            signed_message=TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_2,
        ),
    ),
    TTestVector(
        TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_3,
        Metadata(
            encrypted=False,
            non_repudiation=True,
            authenticated=True,
            anonymous_sender=False,
            sign_from="did:example:alice#key-3",
            sign_alg=SignAlg.ES256K,
            signed_message=TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_3,
        ),
    ),
]
