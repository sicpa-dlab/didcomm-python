from authlib.common.encoding import json_dumps
from authlib.jose import OKPKey, ECKey

from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.core.utils import extract_key
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.secrets.secrets_resolver import Secret


def test_extract_okp_key_from_json_web_key_2020_verification_method():
    key = extract_key(
        VerificationMethod(
            id="did:example:alice#key-x25519-1",
            controller="did:example:alice",
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            public_key_jwk={
                "kty": "OKP",
                "crv": "X25519",
                "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
            },
        ),
        align_kid=True,
    )

    assert isinstance(key, OKPKey)
    assert key.public_only

    assert key.as_dict() == {
        "kty": "OKP",
        "kid": "did:example:alice#key-x25519-1",
        "crv": "X25519",
        "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
    }


def test_extract_okp_key_from_json_web_key_2020_secret():
    key = extract_key(
        Secret(
            kid="did:example:alice#key-ed25519-2",
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,
                value=json_dumps(
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                        "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                    }
                ),
            ),
        ),
        align_kid=True,
    )

    assert isinstance(key, OKPKey)
    assert not key.public_only

    assert key.as_dict(is_private=True) == {
        "kty": "OKP",
        "kid": "did:example:alice#key-ed25519-2",
        "crv": "Ed25519",
        "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
        "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
    }


def test_extract_ec_key_from_json_web_key_2020_verification_method():
    key = extract_key(
        VerificationMethod(
            id="did:example:alice#key-p256-1",
            controller="did:example:alice",
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            public_key_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
            },
        ),
        align_kid=True,
    )

    assert isinstance(key, ECKey)
    assert key.public_only

    assert key.as_dict() == {
        "kty": "EC",
        "kid": "did:example:alice#key-p256-1",
        "crv": "P-256",
        "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
        "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
    }


def test_extract_ec_key_from_json_web_key_2020_secret():
    key = extract_key(
        Secret(
            kid="did:example:alice#key-p256-2",
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
        ),
        align_kid=True,
    )

    assert isinstance(key, ECKey)
    assert not key.public_only

    assert key.as_dict(is_private=True) == {
        "kty": "EC",
        "kid": "did:example:alice#key-p256-2",
        "crv": "P-256",
        "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
        "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
        "d": "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
    }


def test_extract_key_from_x25519_key_agreement_key_2019_verification_method():
    key = extract_key(
        VerificationMethod(
            id="did:example:dave#key-x25519-1",
            controller="did:example:dave",
            type=VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019,
            public_key_base58="JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr",
        ),
        align_kid=True,
    )

    assert isinstance(key, OKPKey)
    assert key.public_only

    assert key.as_dict() == {
        "kty": "OKP",
        "kid": "did:example:dave#key-x25519-1",
        "crv": "X25519",
        "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
    }


def test_extract_key_from_x25519_key_agreement_key_2019_secret():
    key = extract_key(
        Secret(
            kid="did:example:eve#key-x25519-1",
            type=VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.BASE58,
                value="2b5J8uecvwAo9HUGge5NKQ7HoRNKUKCjZ7Fr4mDgWkwqFyjLPWt7rv5kL3UPeG3e4B9Sy4H2Q2zAuWcP2RNtgJ4t",
            ),
        ),
        align_kid=True,
    )

    assert isinstance(key, OKPKey)
    assert not key.public_only

    assert key.as_dict(is_private=True) == {
        "kty": "OKP",
        "kid": "did:example:eve#key-x25519-1",
        "crv": "X25519",
        "x": "piw5XSMkceDeklaHQZXPBLQySyAwF8eZ-vddihdURS0",
        "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg",
    }


def test_extract_key_from_ed25519_verification_key_2018_verification_method():
    key = extract_key(
        VerificationMethod(
            id="did:example:dave#key-ed25519-1",
            controller="did:example:dave",
            type=VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
            public_key_base58="ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7",
        ),
        align_kid=True,
    )

    assert isinstance(key, OKPKey)
    assert key.public_only

    assert key.as_dict() == {
        "kty": "OKP",
        "kid": "did:example:dave#key-ed25519-1",
        "crv": "Ed25519",
        "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
    }


def test_extract_key_from_ed25519_verification_key_2018_secret():
    key = extract_key(
        Secret(
            kid="did:example:eve#key-ed25519-1",
            type=VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.BASE58,
                value="2b5J8uecvwAo9HUGge5NKQ7HoRNKUKCjZ7Fr4mDgWkwqATnLmZDx7Seu6NqTuFKkxuHNT27GcoxVZQCkWJhNvaUQ",
            ),
        ),
        align_kid=True,
    )

    assert isinstance(key, OKPKey)
    assert not key.public_only

    assert key.as_dict(is_private=True) == {
        "kty": "OKP",
        "kid": "did:example:eve#key-ed25519-1",
        "crv": "Ed25519",
        "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
        "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg",
    }


def test_extract_key_from_x25519_key_agreement_key_2020_verification_method():
    key = extract_key(
        VerificationMethod(
            id="did:example:dave#key-x25519-2",
            controller="did:example:dave",
            type=VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020,
            public_key_multibase="z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
        ),
        align_kid=True,
    )

    assert isinstance(key, OKPKey)
    assert key.public_only

    assert key.as_dict() == {
        "kty": "OKP",
        "kid": "did:example:dave#key-x25519-2",
        "crv": "X25519",
        "x": "BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik",
    }


def test_extract_key_from_x25519_key_agreement_key_2020_secret():
    key = extract_key(
        Secret(
            kid="did:example:eve#key-x25519-2",
            type=VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.MULTIBASE,
                value="zshCmpUZKtFrAfudMf7NzD3oR6yhWe6i2434FDktk9CYZfkndn7suDrqnRWvrVDHk95Z7vBRJChFxTgBF9qzq7D3xPe",
            ),
        ),
        align_kid=True,
    )

    assert isinstance(key, OKPKey)
    assert not key.public_only

    assert key.as_dict(is_private=True) == {
        "kty": "OKP",
        "kid": "did:example:eve#key-x25519-2",
        "crv": "X25519",
        "x": "piw5XSMkceDeklaHQZXPBLQySyAwF8eZ-vddihdURS0",
        "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg",
    }


def test_extract_key_from_ed25519_verification_key_2020_verification_method():
    key = extract_key(
        VerificationMethod(
            id="did:example:dave#key-ed25519-2",
            controller="did:example:dave",
            type=VerificationMethodType.ED25519_VERIFICATION_KEY_2020,
            public_key_multibase="z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
        ),
        align_kid=True,
    )

    assert isinstance(key, OKPKey)
    assert key.public_only

    assert key.as_dict() == {
        "kty": "OKP",
        "kid": "did:example:dave#key-ed25519-2",
        "crv": "Ed25519",
        "x": "owBhCbktDjkfS6PdQddT0D3yjSitaSysP3YimJ_YgmA",
    }


def test_extract_key_from_ed25519_verification_key_2020_secret():
    key = extract_key(
        Secret(
            kid="did:example:eve#key-ed25519-2",
            type=VerificationMethodType.ED25519_VERIFICATION_KEY_2020,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.MULTIBASE,
                value="zrv2DyJwnoQWzS74nPkHHdM7NYH27BRNFBG9To7Fca9YzWhfBVa9Mek52H9bJexjdNqxML1F3TGCpjLNkCwwgQDvd5J",
            ),
        ),
        align_kid=True,
    )

    assert isinstance(key, OKPKey)
    assert not key.public_only

    assert key.as_dict(is_private=True) == {
        "kty": "OKP",
        "kid": "did:example:eve#key-ed25519-2",
        "crv": "Ed25519",
        "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
        "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg",
    }
