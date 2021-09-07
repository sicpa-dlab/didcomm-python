from dataclasses import dataclass
from typing import List

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL, DID_URL
from didcomm.core.utils import get_did_and_optionally_kid, get_did, are_keys_compatible
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.errors import DIDDocNotResolvedError, DIDUrlNotFoundError, SecretNotFoundError, IncompatibleCryptoError
from didcomm.secrets.secrets_resolver import Secret


@dataclass
class AuthcryptPackKeys:
    sender_private_key: Secret
    recipient_public_keys: List[VerificationMethod]


@dataclass
class AuthcryptUnpackKeys:
    recipient_private_key: Secret
    sender_public_key: VerificationMethod


async def find_authcrypt_pack_sender_and_recipient_keys(
        frm_did_or_kid: DID_OR_DID_URL,
        to_did_or_kid: DID_OR_DID_URL,
        resolvers_config: ResolversConfig,
) -> AuthcryptPackKeys:
    frm_did, frm_kid = get_did_and_optionally_kid(frm_did_or_kid)
    to_did, to_kid = get_did_and_optionally_kid(to_did_or_kid)

    if frm_kid is None:
        sender_did_doc = await resolvers_config.did_resolver.resolve(frm_did)
        if sender_did_doc is None:
            raise DIDDocNotResolvedError()
        if not sender_did_doc.key_agreement_kids:
            raise DIDUrlNotFoundError()
        sender_kids = sender_did_doc.key_agreement_kids
    else:
        sender_kids = [frm_kid]

    recipient_did_doc = await resolvers_config.did_resolver.resolve(to_did)
    if recipient_did_doc is None:
        raise DIDDocNotResolvedError()

    if to_kid is None:
        if not recipient_did_doc.key_agreement_kids:
            raise DIDUrlNotFoundError()
        recipient_kids = recipient_did_doc.key_agreement_kids
    else:
        if to_kid not in recipient_did_doc.key_agreement_kids:
            raise DIDUrlNotFoundError()
        recipient_kids = [to_kid]

    for skid in sender_kids:
        secret = await resolvers_config.secrets_resolver.get_key(skid)
        if secret is None:
            continue

        verification_methods = []
        for kid in recipient_kids:
            verification_method = recipient_did_doc.get_verification_method(kid)
            if verification_method is None:
                raise DIDUrlNotFoundError()
            if are_keys_compatible(secret, verification_method):
                verification_methods.append(verification_method)

        if verification_methods:
            return AuthcryptPackKeys(secret, verification_methods)

    raise IncompatibleCryptoError()


async def find_authcrypt_unpack_sender_and_recipient_keys(
        frm_kid: DID_URL,
        to_kids: List[DID_URL],
        resolvers_config: ResolversConfig
):
    secret_ids = await resolvers_config.secrets_resolver.get_keys(to_kids)
    if not secret_ids:
        raise SecretNotFoundError()

    frm_did = get_did(frm_kid)
    sender_did_doc = await resolvers_config.did_resolver.resolve(frm_did)
    if sender_did_doc is None:
        raise DIDDocNotResolvedError()
    if not sender_did_doc.key_agreement_kids:
        raise DIDUrlNotFoundError()
    sender_verification_method = sender_did_doc.get_verification_method(frm_kid)
    if sender_verification_method is None:
        raise DIDUrlNotFoundError()

    found = False
    for secret_id in secret_ids:
        secret = await resolvers_config.secrets_resolver.get_key(secret_id)
        if secret is None:
            raise SecretNotFoundError()
        if not are_keys_compatible(secret, sender_verification_method):
            continue
        found = True
        yield AuthcryptUnpackKeys(secret, sender_verification_method)

    if not found:
        raise DIDUrlNotFoundError()
