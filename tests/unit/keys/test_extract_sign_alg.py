from authlib.common.encoding import json_dumps

from didcomm.common.algorithms import SignAlg
from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.core.utils import extract_sign_alg
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.secrets.secrets_resolver import Secret


def test_extract_sign_alg_from_json_web_key_2020_verification_method_with_p256_key():
    verification_method = VerificationMethod(
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

    sign_alg = extract_sign_alg(verification_method)

    assert sign_alg == SignAlg.ES256


def test_extract_sign_alg_from_json_web_key_2020_secret_with_p256_key():
    secret = Secret(
        kid="did:example:alice#key-2",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                    "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
                    "d": "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
                }
            ),
        ),
    )

    sign_alg = extract_sign_alg(secret)

    assert sign_alg == SignAlg.ES256


def test_extract_sign_alg_from_json_web_key_2020_verification_method_with_secp256k1_key():
    verification_method = VerificationMethod(
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

    sign_alg = extract_sign_alg(verification_method)

    assert sign_alg == SignAlg.ES256K


def test_extract_sign_alg_from_json_web_key_2020_secret_with_secp256k1_key():
    secret = Secret(
        kid="did:example:alice#key-3",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
                    "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk",
                    "d": "N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
                }
            ),
        ),
    )

    sign_alg = extract_sign_alg(secret)

    assert sign_alg == SignAlg.ES256K


def test_extract_sign_alg_from_json_web_key_2020_verification_method_with_ed25519_key():
    verification_method = VerificationMethod(
        id="did:example:alice#key-1",
        controller="did:example:alice",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        public_key_jwk={
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
        },
    )

    sign_alg = extract_sign_alg(verification_method)

    assert sign_alg == SignAlg.ED25519


def test_extract_sign_alg_from_json_web_key_2020_secret_with_ed25519_key():
    secret = Secret(
        kid="did:example:alice#key-1",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "OKP",
                    "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                    "crv": "Ed25519",
                    "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                }
            ),
        ),
    )

    sign_alg = extract_sign_alg(secret)

    assert sign_alg == SignAlg.ED25519


def test_extract_sign_alg_from_ed25519_verification_key_2018_verification_method():
    verification_method = VerificationMethod(
        id="did:example:dave#key-ed25519-1",
        controller="did:example:dave",
        type=VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
        public_key_base58="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
    )

    sign_alg = extract_sign_alg(verification_method)

    assert sign_alg == SignAlg.ED25519


def test_extract_sign_alg_from_ed25519_verification_key_2018_secret():
    secret = Secret(
        kid="did:example:eve#key-ed25519-1",
        type=VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.BASE58,
            value="2b5J8uecvwAo9HUGge5NKQ7HoRNKUKCjZ7Fr4mDgWkwqATnLmZDx7Seu6NqTuFKkxuHNT27GcoxVZQCkWJhNvaUQ",
        ),
    )

    sign_alg = extract_sign_alg(secret)

    assert sign_alg == SignAlg.ED25519


def test_extract_sign_alg_from_ed25519_verification_key_2020_verification_method():
    verification_method = VerificationMethod(
        id="did:example:dave#key-ed25519-2",
        controller="did:example:dave",
        type=VerificationMethodType.ED25519_VERIFICATION_KEY_2020,
        public_key_multibase="z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
    )

    sign_alg = extract_sign_alg(verification_method)

    assert sign_alg == SignAlg.ED25519


def test_extract_sign_alg_from_ed25519_verification_key_2020_secret():
    secret = Secret(
        kid="did:example:eve#key-ed25519-2",
        type=VerificationMethodType.ED25519_VERIFICATION_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.MULTIBASE,
            value="zrv2DyJwnoQWzS74nPkHHdM7NYH27BRNFBG9To7Fca9YzWhfBVa9Mek52H9bJexjdNqxML1F3TGCpjLNkCwwgQDvd5J",
        ),
    )

    sign_alg = extract_sign_alg(secret)

    assert sign_alg == SignAlg.ED25519
