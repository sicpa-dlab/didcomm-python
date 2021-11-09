from authlib.common.encoding import json_dumps

from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod, DIDCommService
from didcomm.protocols.routing.forward import (
    PROFILE_DIDCOMM_V2,
    PROFILE_DIDCOMM_AIP2_ENV_RFC587,
)

CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519 = VerificationMethod(
    id="did:example:charlie#key-x25519-1",
    controller="did:example:charlie#key-x25519-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw",
            }
        ),
    ),
)

CHARLIE_AUTH_METHOD_25519 = VerificationMethod(
    id="did:example:charlie#key-1",
    controller="did:example:charlie#key-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
            }
        ),
    ),
)

DID_DOC_CHARLIE = DIDDoc(
    did="did:example:charlie",
    authentication_kids=["did:example:charlie#key-1"],
    key_agreement_kids=["did:example:charlie#key-x25519-1"],
    didcomm_services=[
        DIDCommService(
            id="did:example:123456789abcdefghi#didcomm-1",
            service_endpoint="did:example:mediator2",
            accept=[PROFILE_DIDCOMM_V2, PROFILE_DIDCOMM_AIP2_ENV_RFC587],
            routing_keys=["did:example:mediator1#key-x25519-1"],
        )
    ],
    verification_methods=[
        CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
        CHARLIE_AUTH_METHOD_25519,
    ],
)
