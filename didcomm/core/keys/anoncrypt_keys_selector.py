from typing import List

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL, DID_URL, DID
from didcomm.core.utils import get_did_and_optionally_kid, are_keys_compatible
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.errors import DIDDocNotResolvedError, DIDUrlNotFoundError, SecretNotFoundError
from didcomm.secrets.secrets_resolver import Secret


async def find_anoncrypt_pack_recipient_public_keys(
        to_did_or_kid: DID_OR_DID_URL, resolvers_config: ResolversConfig
) -> List[VerificationMethod]:
    to_did, to_kid = get_did_and_optionally_kid(to_did_or_kid)
    if to_kid is None:
        return await _find_anoncrypt_pack_recipient_public_keys_by_did(to_did, resolvers_config)
    return await _find_anoncrypt_pack_recipient_public_keys_by_kid(to_did, to_kid, resolvers_config)


async def find_anoncrypt_unpack_recipient_private_keys(
        to_kids: List[DID_URL], resolvers_config: ResolversConfig
):
    secret_ids = await resolvers_config.secrets_resolver.get_keys(to_kids)
    if not secret_ids:
        raise DIDUrlNotFoundError()

    found = False
    for secret_id in secret_ids:
        secret = await resolvers_config.secrets_resolver.get_key(secret_id)
        if secret is None:
            raise SecretNotFoundError()
        found = True
        yield secret

    if not found:
        raise DIDUrlNotFoundError()

async def _find_anoncrypt_pack_recipient_public_keys_by_kid(
        to_did: DID, to_kid: DID_URL, resolvers_config: ResolversConfig
) -> List[VerificationMethod]:
    did_doc = await resolvers_config.did_resolver.resolve(to_did)
    if did_doc is None:
        raise DIDDocNotResolvedError()

    if to_kid not in did_doc.key_agreement_kids:
        raise DIDUrlNotFoundError()

    verification_method = did_doc.get_verification_method(to_kid)
    if verification_method is None:
        raise DIDUrlNotFoundError()

    return [verification_method]


async def _find_anoncrypt_pack_recipient_public_keys_by_did(
        to_did: DID, resolvers_config: ResolversConfig
) -> List[VerificationMethod]:
    did_doc = await resolvers_config.did_resolver.resolve(to_did)
    if did_doc is None:
        raise DIDDocNotResolvedError()

    if not did_doc.key_agreement_kids:
        raise DIDUrlNotFoundError()
    kids = did_doc.key_agreement_kids
    if not kids:
        raise DIDUrlNotFoundError()

    # return only verification methods having the same type as the first one
    first_verification_method = did_doc.get_verification_method(kids[0])
    if first_verification_method is None:
        raise DIDUrlNotFoundError()

    verification_methods = []
    for kid in kids:
        verification_method = did_doc.get_verification_method(kid)
        if verification_method is None:
            raise DIDUrlNotFoundError()
        if are_keys_compatible(first_verification_method, verification_method):
            verification_methods.append(verification_method)

    return verification_methods
