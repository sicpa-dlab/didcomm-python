from didcomm import DIDDoc, DIDCommService, VerificationMethod, VerificationMethodType
from didcomm.protocols.routing.forward import (
    PROFILE_DIDCOMM_V2,
    PROFILE_DIDCOMM_AIP2_ENV_RFC587,
)
from tests.test_vectors.common import CHARLIE_DID

CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519 = VerificationMethod(
    id="did:example:charlie#key-x25519-1",
    controller="did:example:charlie",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    public_key_jwk={
        "kty": "OKP",
        "crv": "X25519",
        "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw",
    },
)

CHARLIE_AUTH_METHOD_25519 = VerificationMethod(
    id="did:example:charlie#key-1",
    controller="did:example:charlie",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    public_key_jwk={
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
    },
)

DID_DOC_CHARLIE = DIDDoc(
    id=CHARLIE_DID,
    authentication=["did:example:charlie#key-1"],
    key_agreement=["did:example:charlie#key-x25519-1"],
    service=[
        DIDCommService(
            id="did:example:123456789abcdefghi#didcomm-1",
            service_endpoint="did:example:mediator2#key-x25519-1",
            accept=[PROFILE_DIDCOMM_V2, PROFILE_DIDCOMM_AIP2_ENV_RFC587],
            recipient_keys=[],
            routing_keys=["did:example:mediator1#key-x25519-1"],
        )
    ],
    verification_method=[
        CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
        CHARLIE_AUTH_METHOD_25519,
    ],
)
