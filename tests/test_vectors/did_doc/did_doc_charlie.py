from authlib.common.encoding import json_dumps

from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod

DID_DOC_CHARLIE = DIDDoc(
    did="did:example:charlie",
    authentication_kids=[],
    key_agreement_kids=["did:example:charlie#key-x25519-1"],
    didcomm_services=[],
    verification_methods=[
        VerificationMethod(
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
    ],
)
