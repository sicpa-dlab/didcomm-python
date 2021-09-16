from authlib.common.encoding import json_dumps

from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod, DIDCommService

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
                "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
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
            accept=["didcomm/v2", "didcomm/aip2;env=rfc587"],
            routing_keys=[
                "did:example:mediator2#key-p521-1",
            ],
        )
    ],
    verification_methods=[
        CHARLIE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
        CHARLIE_AUTH_METHOD_25519,
    ],
)
