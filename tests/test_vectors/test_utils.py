from tests.test_vectors.did_doc.did_doc_alice import (
    ALICE_AUTH_METHOD_SECPP256K1,
    ALICE_AUTH_METHOD_P256,
    ALICE_AUTH_METHOD_25519,
    ALICE_AUTH_METHOD_25519_NOT_IN_SECRET,
    ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
    ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
    ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521,
    ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET,
)
from tests.test_vectors.did_doc.did_doc_bob import (
    BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
    DID_DOC_BOB,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_NOT_IN_SECRETS_1,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRETS_1,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_NOT_IN_SECRETS_1,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_NOT_IN_SECRETS_1,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2,
    BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2,
)
from tests.test_vectors.did_doc.mock_did_resolver import DID_DOC_ALICE
from tests.test_vectors.secrets.mock_secrets_resolver_alice import (
    ALICE_SECRET_AUTH_KEY_ED25519,
    ALICE_SECRET_KEY_AGREEMENT_KEY_X25519,
    ALICE_SECRET_KEY_AGREEMENT_KEY_P256,
    ALICE_SECRET_AUTH_KEY_P256,
    ALICE_SECRET_AUTH_KEY_SECP256K1,
    ALICE_SECRET_KEY_AGREEMENT_KEY_P521,
)
from tests.test_vectors.secrets.mock_secrets_resolver_bob import (
    BOB_SECRET_KEY_AGREEMENT_KEY_P521_1,
    BOB_SECRET_KEY_AGREEMENT_KEY_P384_1,
    BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
    BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
    BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
    BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
    BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
    BOB_SECRET_KEY_AGREEMENT_KEY_P384_2,
    BOB_SECRET_KEY_AGREEMENT_KEY_P521_2,
)
from tests.test_vectors.utils import (
    Person,
    get_auth_methods_in_secrets,
    get_auth_methods_not_in_secrets,
    get_key_agreement_methods_in_secrets,
    get_key_agreement_methods_not_in_secrets,
    get_auth_secrets,
    get_key_agreement_secrets,
    KeyAgreementCurveType,
    get_key_agreement_methods,
    get_auth_methods,
)


# ALICE


def test_get_alice_auth_verification_methods_in_secrets():
    expected = [
        ALICE_AUTH_METHOD_25519,
        ALICE_AUTH_METHOD_P256,
        ALICE_AUTH_METHOD_SECPP256K1,
    ]
    assert get_auth_methods_in_secrets(Person.ALICE) == expected


def test_get_alice_auth_verification_methods_not_in_secrets():
    expected = [ALICE_AUTH_METHOD_25519_NOT_IN_SECRET]
    assert get_auth_methods_not_in_secrets(Person.ALICE) == expected


def test_get_alice_key_agreement_verification_methods_in_secrets_all():
    expected = [
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521,
    ]
    assert get_key_agreement_methods_in_secrets(Person.ALICE) == expected


def test_get_alice_key_agreement_verification_methods_in_secrets_x25519():
    expected = [ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519]
    assert (
        get_key_agreement_methods_in_secrets(Person.ALICE, KeyAgreementCurveType.X25519)
        == expected
    )


def test_get_alice_key_agreement_verification_methods_in_secrets_p256():
    expected = [ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256]
    assert (
        get_key_agreement_methods_in_secrets(Person.ALICE, KeyAgreementCurveType.P256)
        == expected
    )


def test_get_alice_key_agreement_verification_methods_in_secrets_p384():
    assert (
        get_key_agreement_methods_in_secrets(Person.ALICE, KeyAgreementCurveType.P384)
        == []
    )


def test_get_alice_key_agreement_verification_methods_in_secrets_p521():
    expected = [ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521]
    assert (
        get_key_agreement_methods_in_secrets(Person.ALICE, KeyAgreementCurveType.P521)
        == expected
    )


def test_get_alice_key_agreement_verification_methods_not_in_secrets_all():
    expected = [ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET]
    assert get_key_agreement_methods_not_in_secrets(Person.ALICE) == expected


def test_get_alice_key_agreement_verification_methods_not_in_secrets_x25519():
    expected = [ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET]
    assert (
        get_key_agreement_methods_not_in_secrets(
            Person.ALICE, KeyAgreementCurveType.X25519
        )
        == expected
    )


def test_get_alice_key_agreement_verification_methods_not_in_secrets_p256():
    assert (
        get_key_agreement_methods_not_in_secrets(
            Person.ALICE, KeyAgreementCurveType.P256
        )
        == []
    )


def test_get_alice_key_agreement_verification_methods_not_in_secrets_p384():
    assert (
        get_key_agreement_methods_not_in_secrets(
            Person.ALICE, KeyAgreementCurveType.P384
        )
        == []
    )


def test_get_alice_key_agreement_verification_methods_not_in_secrets_p521():
    assert (
        get_key_agreement_methods_not_in_secrets(
            Person.ALICE, KeyAgreementCurveType.P521
        )
        == []
    )


def test_get_alice_authentication_secrets():
    expected = [
        ALICE_SECRET_AUTH_KEY_ED25519,
        ALICE_SECRET_AUTH_KEY_P256,
        ALICE_SECRET_AUTH_KEY_SECP256K1,
    ]
    assert get_auth_secrets(Person.ALICE) == expected


def test_get_alice_key_agreement_secrets_all():
    expected = [
        ALICE_SECRET_KEY_AGREEMENT_KEY_X25519,
        ALICE_SECRET_KEY_AGREEMENT_KEY_P256,
        ALICE_SECRET_KEY_AGREEMENT_KEY_P521,
    ]
    assert get_key_agreement_secrets(Person.ALICE) == expected


def test_get_alice_key_agreement_secrets_x25519():
    expected = [ALICE_SECRET_KEY_AGREEMENT_KEY_X25519]
    assert (
        get_key_agreement_secrets(Person.ALICE, KeyAgreementCurveType.X25519)
        == expected
    )


def test_get_alice_key_agreement_secrets_p256():
    expected = [ALICE_SECRET_KEY_AGREEMENT_KEY_P256]
    assert (
        get_key_agreement_secrets(Person.ALICE, KeyAgreementCurveType.P256) == expected
    )


def test_get_alice_key_agreement_secrets_p384():
    assert get_key_agreement_secrets(Person.ALICE, KeyAgreementCurveType.P384) == []


def test_get_alice_key_agreement_secrets_p521():
    expected = [ALICE_SECRET_KEY_AGREEMENT_KEY_P521]
    assert (
        get_key_agreement_secrets(Person.ALICE, KeyAgreementCurveType.P521) == expected
    )


def test_get_alice_key_agreement_methods_all():
    expected = [
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521,
    ]
    assert get_key_agreement_methods(Person.ALICE) == expected


def test_get_alice_key_agreement_methods_x25519():
    expected = [
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRET,
        ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519,
    ]
    assert (
        get_key_agreement_methods(Person.ALICE, KeyAgreementCurveType.X25519)
        == expected
    )


def test_get_alice_key_agreement_methods_p256():
    expected = [ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256]
    assert (
        get_key_agreement_methods(Person.ALICE, KeyAgreementCurveType.P256) == expected
    )


def test_get_alice_key_agreement_methods_p384():
    assert get_key_agreement_methods(Person.ALICE, KeyAgreementCurveType.P384) == []


def test_get_alice_key_agreement_methods_p521():
    expected = [ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521]
    assert (
        get_key_agreement_methods(Person.ALICE, KeyAgreementCurveType.P521) == expected
    )


def test_get_alice_authentication_methods():
    expected = [
        ALICE_AUTH_METHOD_25519_NOT_IN_SECRET,
        ALICE_AUTH_METHOD_25519,
        ALICE_AUTH_METHOD_P256,
        ALICE_AUTH_METHOD_SECPP256K1,
    ]
    assert get_auth_methods(Person.ALICE) == expected


def test_alice_first_key_agreement_is_x25519():
    assert (
        get_key_agreement_methods(Person.ALICE, KeyAgreementCurveType.X25519)[0]
        == DID_DOC_ALICE.verification_methods[0]
    )


# BOB


def test_get_bob_auth_verification_methods_in_secrets():
    assert get_auth_methods_in_secrets(Person.BOB) == []


def test_get_bob_auth_verification_methods_not_in_secrets():
    assert get_auth_methods_not_in_secrets(Person.BOB) == []


def test_get_bob_key_agreement_verification_methods_in_secrets_all():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2,
    ]
    assert get_key_agreement_methods_in_secrets(Person.BOB) == expected


def test_get_bob_key_agreement_verification_methods_in_secrets_x25519():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3,
    ]
    assert (
        get_key_agreement_methods_in_secrets(Person.BOB, KeyAgreementCurveType.X25519)
        == expected
    )


def test_get_bob_key_agreement_verification_methods_in_secrets_p256():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2,
    ]
    assert (
        get_key_agreement_methods_in_secrets(Person.BOB, KeyAgreementCurveType.P256)
        == expected
    )


def test_get_bob_key_agreement_verification_methods_in_secrets_p384():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2,
    ]
    assert (
        get_key_agreement_methods_in_secrets(Person.BOB, KeyAgreementCurveType.P384)
        == expected
    )


def test_get_bob_key_agreement_verification_methods_in_secrets_p521():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2,
    ]
    assert (
        get_key_agreement_methods_in_secrets(Person.BOB, KeyAgreementCurveType.P521)
        == expected
    )


def test_get_bob_key_agreement_verification_methods_not_in_secrets_all():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRETS_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_NOT_IN_SECRETS_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_NOT_IN_SECRETS_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_NOT_IN_SECRETS_1,
    ]
    assert get_key_agreement_methods_not_in_secrets(Person.BOB) == expected


def test_get_bob_key_agreement_verification_methods_not_in_secrets_x25519():
    expected = [BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRETS_1]
    assert (
        get_key_agreement_methods_not_in_secrets(
            Person.BOB, KeyAgreementCurveType.X25519
        )
        == expected
    )


def test_get_bob_key_agreement_verification_methods_not_in_secrets_p256():
    expected = [BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_NOT_IN_SECRETS_1]
    assert (
        get_key_agreement_methods_not_in_secrets(Person.BOB, KeyAgreementCurveType.P256)
        == expected
    )


def test_get_bob_key_agreement_verification_methods_not_in_secrets_p384():
    expected = [BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_NOT_IN_SECRETS_1]
    assert (
        get_key_agreement_methods_not_in_secrets(Person.BOB, KeyAgreementCurveType.P384)
        == expected
    )


def test_get_bob_key_agreement_verification_methods_not_in_secrets_p521():
    expected = [BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_NOT_IN_SECRETS_1]
    assert (
        get_key_agreement_methods_not_in_secrets(Person.BOB, KeyAgreementCurveType.P521)
        == expected
    )


def test_get_bob_authentication_secrets():
    assert get_auth_secrets(Person.BOB) == []


def test_get_bob_key_agreement_secrets_all():
    expected = [
        BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
        BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
        BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
        BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
        BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
        BOB_SECRET_KEY_AGREEMENT_KEY_P384_1,
        BOB_SECRET_KEY_AGREEMENT_KEY_P384_2,
        BOB_SECRET_KEY_AGREEMENT_KEY_P521_1,
        BOB_SECRET_KEY_AGREEMENT_KEY_P521_2,
    ]
    assert get_key_agreement_secrets(Person.BOB) == expected


def test_get_bob_key_agreement_secrets_x25519():
    expected = [
        BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1,
        BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2,
        BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3,
    ]
    assert (
        get_key_agreement_secrets(Person.BOB, KeyAgreementCurveType.X25519) == expected
    )


def test_get_bob_key_agreement_secrets_p256():
    expected = [
        BOB_SECRET_KEY_AGREEMENT_KEY_P256_1,
        BOB_SECRET_KEY_AGREEMENT_KEY_P256_2,
    ]
    assert get_key_agreement_secrets(Person.BOB, KeyAgreementCurveType.P256) == expected


def test_get_bob_key_agreement_secrets_p384():
    expected = [
        BOB_SECRET_KEY_AGREEMENT_KEY_P384_1,
        BOB_SECRET_KEY_AGREEMENT_KEY_P384_2,
    ]
    assert get_key_agreement_secrets(Person.BOB, KeyAgreementCurveType.P384) == expected


def test_get_bob_key_agreement_secrets_p521():
    expected = [
        BOB_SECRET_KEY_AGREEMENT_KEY_P521_1,
        BOB_SECRET_KEY_AGREEMENT_KEY_P521_2,
    ]
    assert get_key_agreement_secrets(Person.BOB, KeyAgreementCurveType.P521) == expected


def test_get_bob_key_agreement_methods_all():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRETS_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_NOT_IN_SECRETS_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_NOT_IN_SECRETS_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_NOT_IN_SECRETS_1,
    ]
    assert get_key_agreement_methods(Person.BOB) == expected


def test_get_bob_key_agreement_methods_x25519():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRETS_1,
    ]
    assert (
        get_key_agreement_methods(Person.BOB, KeyAgreementCurveType.X25519) == expected
    )


def test_get_bob_key_agreement_methods_p256():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_NOT_IN_SECRETS_1,
    ]
    assert get_key_agreement_methods(Person.BOB, KeyAgreementCurveType.P256) == expected


def test_get_bob_key_agreement_methods_p384():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_NOT_IN_SECRETS_1,
    ]
    assert get_key_agreement_methods(Person.BOB, KeyAgreementCurveType.P384) == expected


def test_get_bob_key_agreement_methods_p521():
    expected = [
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_NOT_IN_SECRETS_1,
    ]
    assert get_key_agreement_methods(Person.BOB, KeyAgreementCurveType.P521) == expected


def test_get_bob_authentication_methods():
    expected = []
    assert get_auth_methods(Person.BOB) == expected


def test_bob_first_key_agreement_is_x25519():
    assert (
        get_key_agreement_methods(Person.BOB, KeyAgreementCurveType.X25519)[0]
        == DID_DOC_BOB.verification_methods[0]
    )
