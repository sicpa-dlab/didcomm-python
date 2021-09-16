from enum import Enum
from typing import List, Union

from didcomm.common.types import VerificationMethodType, VerificationMaterialFormat
from didcomm.core.serialization import json_str_to_dict
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.secrets.secrets_resolver import Secret
from tests.test_vectors.did_doc import (
    DID_DOC_ALICE_WITH_NO_SECRETS,
    DID_DOC_BOB_WITH_NO_SECRETS,
    DID_DOC_CHARLIE,
    DID_DOC_MEDIATOR1,
    DID_DOC_MEDIATOR2,
)
from tests.test_vectors.secrets import (
    MockSecretsResolverAlice,
    MockSecretsResolverBob,
    MockSecretsResolverCharlie,
    MockSecretsResolverMediator1,
    MockSecretsResolverMediator2,
)


class Person(Enum):
    ALICE = 1
    BOB = 2
    CHARLIE = 3
    MEDIATOR1 = 4
    MEDIATOR2 = 5


class KeyAgreementCurveType(Enum):
    ALL = 0
    X25519 = 1
    P256 = 2
    P384 = 3
    P521 = 4


did_docs_spec = {
    Person.ALICE: (DID_DOC_ALICE_WITH_NO_SECRETS, MockSecretsResolverAlice),
    Person.BOB: (DID_DOC_BOB_WITH_NO_SECRETS, MockSecretsResolverBob),
    Person.CHARLIE: (DID_DOC_CHARLIE, MockSecretsResolverCharlie),
    Person.MEDIATOR1: (DID_DOC_MEDIATOR1, MockSecretsResolverMediator1),
    Person.MEDIATOR2: (DID_DOC_MEDIATOR2, MockSecretsResolverMediator2),
}


def _get_did_doc(person: Person):
    spec = did_docs_spec.get(person)
    return spec[0] if spec else None


def _get_secrets_resolver(person: Person):
    spec = did_docs_spec.get(person)
    return spec[1]() if spec else None


def get_auth_methods_in_secrets(person: Person) -> List[VerificationMethod]:
    did_doc = _get_did_doc(person)
    secrets_resolver = _get_secrets_resolver(person)
    return [
        vm
        for vm in did_doc.verification_methods
        if vm.id in secrets_resolver.get_secret_kids()
        and vm.id in did_doc.authentication_kids
    ]


def get_auth_methods_not_in_secrets(person: Person) -> List[VerificationMethod]:
    did_doc = _get_did_doc(person)
    secrets_resolver = _get_secrets_resolver(person)
    return [
        vm
        for vm in did_doc.verification_methods
        if vm.id not in secrets_resolver.get_secret_kids()
        and vm.id in did_doc.authentication_kids
    ]


def get_key_agreement_methods_in_secrets(
    person: Person, type: KeyAgreementCurveType = KeyAgreementCurveType.ALL
) -> List[VerificationMethod]:
    did_doc = _get_did_doc(person)
    secrets_resolver = _get_secrets_resolver(person)
    return [
        vm
        for vm in did_doc.verification_methods
        if vm.id in secrets_resolver.get_secret_kids()
        and vm.id in did_doc.key_agreement_kids
        and (type == KeyAgreementCurveType.ALL or type == _map_cure_to_type(vm))
    ]


def get_key_agreement_methods_not_in_secrets(
    person: Person, type: KeyAgreementCurveType = KeyAgreementCurveType.ALL
) -> List[VerificationMethod]:
    did_doc = _get_did_doc(person)
    secrets_resolver = _get_secrets_resolver(person)
    return [
        vm
        for vm in did_doc.verification_methods
        if vm.id not in secrets_resolver.get_secret_kids()
        and vm.id in did_doc.key_agreement_kids
        and (type == KeyAgreementCurveType.ALL or type == _map_cure_to_type(vm))
    ]


def get_auth_secrets(person: Person) -> List[Secret]:
    did_doc = _get_did_doc(person)
    secrets_resolver = _get_secrets_resolver(person)
    return [
        s
        for s in secrets_resolver.get_secrets()
        if s.kid in did_doc.authentication_kids
    ]


def get_key_agreement_secrets(
    person: Person, type: KeyAgreementCurveType = KeyAgreementCurveType.ALL
) -> List[Secret]:
    did_doc = _get_did_doc(person)
    secrets_resolver = _get_secrets_resolver(person)
    return [
        s
        for s in secrets_resolver.get_secrets()
        if s.kid in did_doc.key_agreement_kids
        and (type == KeyAgreementCurveType.ALL or type == _map_cure_to_type(s))
    ]


def get_auth_methods(person: Person) -> List[VerificationMethod]:
    did_doc = _get_did_doc(person)
    return [
        vm
        for vm in did_doc.verification_methods
        if vm.id in did_doc.authentication_kids
    ]


def get_key_agreement_methods(
    person: Person, type: KeyAgreementCurveType = KeyAgreementCurveType.ALL
) -> List[VerificationMethod]:
    did_doc = _get_did_doc(person)
    return [
        vm
        for vm in did_doc.verification_methods
        if vm.id in did_doc.key_agreement_kids
        and (type == KeyAgreementCurveType.ALL or type == _map_cure_to_type(vm))
    ]


def _map_cure_to_type(vm: Union[Secret, VerificationMethod]) -> KeyAgreementCurveType:
    if vm.type == VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019:
        return KeyAgreementCurveType.X25519
    if (
        vm.type == VerificationMethodType.JSON_WEB_KEY_2020
        and vm.verification_material.format == VerificationMaterialFormat.JWK
    ):
        jwk = json_str_to_dict(vm.verification_material.value)
        if jwk["crv"] == "X25519":
            return KeyAgreementCurveType.X25519
        if jwk["crv"] == "P-256":
            return KeyAgreementCurveType.P256
        if jwk["crv"] == "P-384":
            return KeyAgreementCurveType.P384
        if jwk["crv"] == "P-521":
            return KeyAgreementCurveType.P521
    raise ValueError("Unknown verification methods curve type: " + str(vm))
