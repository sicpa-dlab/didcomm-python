from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL, DID_URL
from didcomm.core.utils import get_did_and_optionally_kid, get_did
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.errors import (
    DIDDocNotResolvedError,
    DIDUrlNotFoundError,
    SecretNotFoundError,
)
from didcomm.secrets.secrets_resolver import Secret


async def find_signing_key(
    frm_did_or_kid: DID_OR_DID_URL, resolvers_config: ResolversConfig
) -> Secret:
    frm_did, frm_kid = get_did_and_optionally_kid(frm_did_or_kid)

    if frm_kid is None:
        return await _find_signing_key_by_did(frm_did, resolvers_config)
    return await _find_signing_key_by_kid(frm_kid, resolvers_config)


async def find_verification_key(
    frm_kid: DID_URL, resolvers_config: ResolversConfig
) -> VerificationMethod:
    did = get_did(frm_kid)

    did_doc = await resolvers_config.did_resolver.resolve(did)
    if did_doc is None:
        raise DIDDocNotResolvedError()

    if frm_kid not in did_doc.authentication_kids:
        raise DIDUrlNotFoundError()

    verification_method = did_doc.get_verification_method(frm_kid)
    if verification_method is None:
        raise DIDUrlNotFoundError()

    return verification_method


async def _find_signing_key_by_kid(
    frm_kid: DID_URL, resolvers_config: ResolversConfig
) -> Secret:
    secret = await resolvers_config.secrets_resolver.get_key(frm_kid)
    if secret is None:
        raise SecretNotFoundError()

    return secret


async def _find_signing_key_by_did(
    frm_did: DID_OR_DID_URL, resolvers_config: ResolversConfig
) -> Secret:
    did_doc = await resolvers_config.did_resolver.resolve(frm_did)
    if did_doc is None:
        raise DIDDocNotResolvedError()

    if not did_doc.authentication_kids:
        raise DIDUrlNotFoundError()

    secret_ids = await resolvers_config.secrets_resolver.get_keys(
        did_doc.authentication_kids
    )
    if not secret_ids:
        raise SecretNotFoundError()

    kid = secret_ids[0]
    secret = await resolvers_config.secrets_resolver.get_key(kid)
    if secret is None:
        raise SecretNotFoundError()

    return secret
