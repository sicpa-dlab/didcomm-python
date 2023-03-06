from didcomm import (
    VerificationMethod,
    VerificationMethodType,
    DIDDoc,
    DIDCommService,
)
from didcomm.protocols.routing.forward import (
    PROFILE_DIDCOMM_V2,
    PROFILE_DIDCOMM_AIP2_ENV_RFC587,
)

ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET = VerificationMethod(
    id="did:example:alice#key-x25519-not-in-secrets-1",
    controller="did:example:alice",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    public_key_jwk={
        "kty": "OKP",
        "crv": "X25519",
        "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
    },
)
ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519 = VerificationMethod(
    id="did:example:alice#key-x25519-1",
    controller="did:example:alice",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    public_key_jwk={
        "kty": "OKP",
        "crv": "X25519",
        "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
    },
)
ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256 = VerificationMethod(
    id="did:example:alice#key-p256-1",
    controller="did:example:alice",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    public_key_jwk={
        "kty": "EC",
        "crv": "P-256",
        "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
        "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
    },
)
ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521 = VerificationMethod(
    id="did:example:alice#key-p521-1",
    controller="did:example:alice",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    public_key_jwk={
        "kty": "EC",
        "crv": "P-521",
        "x": "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
        "y": "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk",
    },
)

ALICE_AUTH_METHOD_25519_NOT_IN_SECRET = VerificationMethod(
    id="did:example:alice#key-not-in-secrets-1",
    controller="did:example:alice",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    public_key_jwk={
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
    },
)
ALICE_AUTH_METHOD_25519 = VerificationMethod(
    id="did:example:alice#key-1",
    controller="did:example:alice",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    public_key_jwk={
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
    },
)
ALICE_AUTH_METHOD_P256 = VerificationMethod(
    id="did:example:alice#key-2",
    controller="did:example:alice",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    public_key_jwk={
        "kty": "EC",
        "crv": "P-256",
        "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
        "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
    },
)
ALICE_AUTH_METHOD_SECPP256K1 = VerificationMethod(
    id="did:example:alice#key-3",
    controller="did:example:alice",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    public_key_jwk={
        "kty": "EC",
        "crv": "secp256k1",
        "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
        "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk",
    },
)

DID_DOC_ALICE_SPEC_TEST_VECTORS = DIDDoc(
    id="did:example:alice",
    authentication=[
        "did:example:alice#key-1",
        "did:example:alice#key-2",
        "did:example:alice#key-3",
    ],
    key_agreement=[
        "did:example:alice#key-x25519-not-in-secrets-1",
        "did:example:alice#key-x25519-1",
        "did:example:alice#key-p256-1",
        "did:example:alice#key-p521-1",
    ],
    service=[
        DIDCommService(
            id="did:example:123456789abcdefghi#didcomm-1",
            service_endpoint="did:example:mediator1#random",
            accept=[PROFILE_DIDCOMM_V2, PROFILE_DIDCOMM_AIP2_ENV_RFC587],
            routing_keys=[
                "did:example:mediator2#key-p521-1",
            ],
            recipient_keys=["did:example:alice#key-1"],
        )
    ],
    verification_method=[
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521,
        ALICE_AUTH_METHOD_25519_NOT_IN_SECRET,
        ALICE_AUTH_METHOD_25519,
        ALICE_AUTH_METHOD_P256,
        ALICE_AUTH_METHOD_SECPP256K1,
    ],
)

DID_DOC_ALICE_WITH_NO_SECRETS = DIDDoc(
    id="did:example:alice",
    authentication=[
        "did:example:alice#key-not-in-secrets-1",
        "did:example:alice#key-1",
        "did:example:alice#key-2",
        "did:example:alice#key-3",
    ],
    key_agreement=[
        "did:example:alice#key-x25519-not-in-secrets-1",
        "did:example:alice#key-x25519-1",
        "did:example:alice#key-p256-1",
        "did:example:alice#key-p521-1",
    ],
    service=[],
    verification_method=[
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521,
        ALICE_AUTH_METHOD_25519_NOT_IN_SECRET,
        ALICE_AUTH_METHOD_25519,
        ALICE_AUTH_METHOD_P256,
        ALICE_AUTH_METHOD_SECPP256K1,
    ],
)
