from typing import Union, List, Optional

from authlib.common.encoding import json_loads
from authlib.jose import ECKey, OKPKey
from authlib.jose.rfc7517 import AsymmetricKey

from didcomm.common.algorithms import SignAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import VerificationMaterialFormat, VerificationMethodType, DID_OR_DID_URL, DID_URL, DID
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.errors import DIDUrlNotFoundError, SecretNotFoundError, IncompatibleCryptoError
from didcomm.secrets.secrets_resolver import Secret


def extract_key(verification_method: Union[VerificationMethod, Secret]) -> AsymmetricKey:
    if verification_method.verification_material.format == VerificationMaterialFormat.JWK:
        jwk = json_loads(verification_method.verification_material.value)
        if jwk['kty'] == 'EC':
            return ECKey.import_key(jwk)
        elif jwk['kty'] == 'OKP':
            return OKPKey.import_key(jwk)
        else:
            # FIXME
            raise NotImplemented()
    else:
        # FIXME
        raise NotImplemented()


def extract_sign_alg(verification_method: Union[VerificationMethod, Secret]) -> SignAlg:
    if verification_method.type == VerificationMethodType.JSON_WEB_KEY_2020 and \
            verification_method.verification_material.format == VerificationMaterialFormat.JWK:
        jwk = json_loads(verification_method.verification_material.value)
        if jwk['kty'] == 'EC' and jwk['crv'] == 'P-256':
            return SignAlg.ES256
        elif jwk['kty'] == 'EC' and jwk['crv'] == 'secp256k1':
            return SignAlg.ES256K
        elif jwk['kty'] == 'OKP' and jwk['crv'] == 'Ed25519':
            return SignAlg.ED25519
        else:
            # FIXME
            raise NotImplemented()
    elif verification_method.type == VerificationMethodType.ED25519_VERIFICATION_KEY_2018:
        return SignAlg.ED25519
    elif verification_method.type == VerificationMethodType.ECDSA_SECP_256K1_VERIFICATION_KEY_2019:
        return SignAlg.ES256K
    else:
        # FIXME
        raise NotImplemented()


def is_did_url(did_or_did_url: DID_OR_DID_URL) -> bool:
    return '#' in did_or_did_url


def get_did(did_or_did_url: DID_OR_DID_URL) -> DID:
    return did_or_did_url.partition('#')[0]


def get_did_and_optionally_kid(did_or_kid: DID_OR_DID_URL) -> (DID, Optional[DID_URL]):
    if is_did_url(did_or_kid):
        did = get_did(did_or_kid)
        kid = did_or_kid
    else:
        did = did_or_kid
        kid = None
    return did, kid


def are_keys_compatible(
        secret: Secret,
        verification_method: VerificationMethod
) -> bool:
    if secret.type == verification_method.type and \
            secret.verification_material.format == verification_method.verification_material.format:
        if secret.verification_material.format == VerificationMaterialFormat.JWK:
            private_jwk = json_loads(secret.verification_material.value)
            public_jwk = json_loads(verification_method.verification_material.value)
            return private_jwk['kty'] == public_jwk['kty'] and private_jwk['crv'] == public_jwk['crv']
        else:
            return True
    else:
        return False


async def find_authentication_secret(
        did_or_kid: DID_OR_DID_URL,
        resolvers_config: ResolversConfig
) -> Secret:

    did, kid = get_did_and_optionally_kid(did_or_kid)

    did_doc = await resolvers_config.did_resolver.resolve(did)

    if kid is None:
        if not did_doc.authentication_kids():
            raise DIDUrlNotFoundError()

        secret_ids = await resolvers_config.secrets_resolver.get_keys(did_doc.authentication_kids())
        if not secret_ids:
            raise SecretNotFoundError()

        kid = secret_ids[0]
        secret = await resolvers_config.secrets_resolver.get_key(kid)

    else:
        if kid not in did_doc.authentication_kids():
            raise DIDUrlNotFoundError()

        secret = await resolvers_config.secrets_resolver.get_key(kid)
        if secret is None:
            raise SecretNotFoundError()

    return secret


async def find_authentication_verification_method(
        kid: DID_URL,
        resolvers_config: ResolversConfig
) -> VerificationMethod:

    did = get_did(kid)

    did_doc = await resolvers_config.did_resolver.resolve(did)

    if kid not in did_doc.authentication_kids():
        raise DIDUrlNotFoundError()

    verification_method = did_doc.get_verification_method(kid)
    if verification_method is None:
        raise DIDUrlNotFoundError()

    return verification_method


async def find_key_agreement_recipient_verification_methods(
        did_or_kid: DID_OR_DID_URL,
        resolvers_config: ResolversConfig
) -> List[VerificationMethod]:

    did, kid = get_did_and_optionally_kid(did_or_kid)

    did_doc = await resolvers_config.did_resolver.resolve(did)

    if kid is None:
        if not did_doc.key_agreement_kids():
            raise DIDUrlNotFoundError()
        kids = did_doc.key_agreement_kids()
    else:
        if kid not in did_doc.key_agreement_kids():
            raise DIDUrlNotFoundError()
        kids = [kid]

    verification_methods = []

    for kid in kids:
        verification_method = did_doc.get_verification_method(kid)
        if verification_method is None:
            raise DIDUrlNotFoundError()
        verification_methods.append(verification_method)

    return verification_methods


async def find_key_agreement_secret_and_verification_methods(
        sender_did_or_kid: DID_OR_DID_URL,
        recipient_did_or_kid: DID_OR_DID_URL,
        resolvers_config: ResolversConfig
) -> (Secret, List[VerificationMethod]):

    sender_did, sender_kid = get_did_and_optionally_kid(sender_did_or_kid)
    recipient_did, recipient_kid = get_did_and_optionally_kid(recipient_did_or_kid)

    sender_did_doc = await resolvers_config.did_resolver.resolve(sender_did)
    recipient_did_doc = await resolvers_config.did_resolver.resolve(recipient_did)

    if sender_kid is None:
        if not sender_did_doc.key_agreement_kids():
            raise DIDUrlNotFoundError()
        sender_kids = sender_did_doc.key_agreement_kids()
    else:
        if sender_kid not in sender_did_doc.key_agreement_kids():
            raise DIDUrlNotFoundError()
        sender_kids = [sender_kid]

    if recipient_kid is None:
        if not recipient_did_doc.key_agreement_kids():
            raise DIDUrlNotFoundError()
        recipient_kids = recipient_did_doc.key_agreement_kids()
    else:
        if recipient_kid not in recipient_did_doc.key_agreement_kids():
            raise DIDUrlNotFoundError()
        recipient_kids = [recipient_kid]

    for skid in sender_kids:
        secret = await resolvers_config.secrets_resolver.get_key(skid)
        if secret is None:
            raise SecretNotFoundError()

        verification_methods = []

        for kid in recipient_kids:
            verification_method = recipient_did_doc.get_verification_method(kid)
            if verification_method is None:
                raise DIDUrlNotFoundError()
            if are_keys_compatible(secret, verification_method):
                verification_methods.append(verification_method)

        if verification_methods:
            return secret, verification_methods

    raise IncompatibleCryptoError()


async def find_key_agreement_recipient_secrets(
        kids: List[DID_URL],
        resolvers_config: ResolversConfig
) -> List[Secret]:

    dids = {get_did(kid) for kid in kids}
    if len(dids) > 1:
        # FIXME: Provide appropriate exception type
        raise ValueError()

    did = next(iter(dids))

    did_doc = await resolvers_config.did_resolver.resolve(did)

    for kid in kids:
        if kid not in did_doc.key_agreement_kids():
            raise DIDUrlNotFoundError()

    secret_ids = await resolvers_config.secrets_resolver.get_keys(kids)
    if not secret_ids:
        raise SecretNotFoundError()

    secrets = []

    for secret_id in secret_ids:
        secret = await resolvers_config.secrets_resolver.get_key(secret_id)
        if secret is None:
            raise SecretNotFoundError()
        secrets.append(secret)

    return secrets


async def find_key_agreement_sender_verification_method(
        kid: DID_URL,
        resolvers_config: ResolversConfig
) -> VerificationMethod:

    did = get_did(kid)

    did_doc = await resolvers_config.did_resolver.resolve(did)

    if kid not in did_doc.key_agreement_kids():
        raise DIDUrlNotFoundError()

    verification_method = did_doc.get_verification_method(kid)
    if verification_method is None:
        raise DIDUrlNotFoundError()

    return verification_method
