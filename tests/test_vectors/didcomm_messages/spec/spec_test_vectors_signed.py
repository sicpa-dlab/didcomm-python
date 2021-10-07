import copy

from didcomm.vendor.authlib.common.encoding import json_dumps

from didcomm.common.algorithms import SignAlg
from didcomm.unpack import Metadata
from tests.test_vectors.common import TTestVector

TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_1 = json_dumps(
    {
        "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures": [
            {
                "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                "signature": "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                "header": {"kid": "did:example:alice#key-1"},
            }
        ],
    }
)

TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_2 = json_dumps(
    {
        "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures": [
            {
                "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTYifQ",
                "signature": "gcW3lVifhyR48mLHbbpnGZQuziskR5-wXf6IoBlpa9SzERfSG9I7oQ9pssmHZwbvJvyMvxskpH5oudw1W3X5Qg",
                "header": {"kid": "did:example:alice#key-2"},
            }
        ],
    }
)

TEST_SIGNED_DIDCOMM_MESSAGE_ALICE_KEY_3 = json_dumps(
    {
        "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures": [
            {
                "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRVMyNTZLIn0",
                "signature": "EGjhIcts6tqiJgqtxaTiTY3EUvL-_rLjn9lxaZ4eRUwa1-CS1nknZoyJWbyY5NQnUafWh5nvCtQpdpMyzH3blw",
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
