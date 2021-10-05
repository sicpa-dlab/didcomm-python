import pytest

from didcomm.common.types import VerificationMethodType, VerificationMaterialFormat
from didcomm.secrets.secrets_util import (
    generate_ed25519_keys_as_jwk_dict,
    generate_x25519_keys_as_jwk_dict,
    jwk_to_secret,
    secret_to_jwk_dict,
)


def test_generate_ed25519_keys_as_jwk_dict():
    private_key, public_key = generate_ed25519_keys_as_jwk_dict()
    assert private_key is not None
    assert public_key is not None
    assert isinstance(private_key, dict)
    assert isinstance(public_key, dict)
    assert private_key["crv"] == "Ed25519"
    assert public_key["crv"] == "Ed25519"
    assert private_key["kty"] == "OKP"
    assert public_key["kty"] == "OKP"
    assert "x" in private_key
    assert "d" in private_key
    assert "x" in public_key
    assert "d" not in public_key


def test_generate_x25519_keys_as_jwk_dict():
    private_key, public_key = generate_x25519_keys_as_jwk_dict()
    assert private_key is not None
    assert public_key is not None
    assert isinstance(private_key, dict)
    assert isinstance(public_key, dict)
    assert private_key["crv"] == "X25519"
    assert public_key["crv"] == "X25519"
    assert private_key["kty"] == "OKP"
    assert public_key["kty"] == "OKP"
    assert "x" in private_key
    assert "d" in private_key
    assert "x" in public_key
    assert "d" not in public_key


@pytest.mark.parametrize(
    "private_key",
    [
        pytest.param(generate_ed25519_keys_as_jwk_dict()[0], id="ed25519"),
        pytest.param(generate_x25519_keys_as_jwk_dict()[0], id="x25519"),
    ],
)
def test_ed25519_jwk_to_secret(private_key):
    secret = jwk_to_secret(private_key)
    assert secret.type == VerificationMethodType.JSON_WEB_KEY_2020
    assert secret.kid == private_key["kid"]
    assert secret.verification_material.format == VerificationMaterialFormat.JWK
    assert isinstance(secret.verification_material.value, str)  # expect JSON


@pytest.mark.parametrize(
    "private_key",
    [
        pytest.param(generate_ed25519_keys_as_jwk_dict()[0], id="ed25519"),
        pytest.param(generate_x25519_keys_as_jwk_dict()[0], id="x25519"),
    ],
)
def test_ed25519_secret_to_jwk(private_key):
    secret = jwk_to_secret(private_key)
    jwk = secret_to_jwk_dict(secret)
    assert private_key == jwk


@pytest.mark.parametrize(
    "private_key",
    [
        pytest.param(generate_ed25519_keys_as_jwk_dict()[0], id="ed25519"),
        pytest.param(generate_x25519_keys_as_jwk_dict()[0], id="x25519"),
    ],
)
def test_ed25519_secret_to_jwk_updates_kid(private_key):
    secret = jwk_to_secret(private_key)
    secret.kid = "my-secret"
    jwk = secret_to_jwk_dict(secret)
    assert jwk["kid"] == "my-secret"
    del private_key["kid"]
    del jwk["kid"]
    assert private_key == jwk
