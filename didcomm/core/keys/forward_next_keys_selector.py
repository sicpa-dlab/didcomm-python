from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL
from didcomm.core.utils import is_did_with_uri_fragment


async def has_keys_for_forward_next(
    _next: DID_OR_DID_URL, resolvers_config: ResolversConfig
) -> bool:
    if is_did_with_uri_fragment(_next):
        next_kids = [_next]
    else:
        next_did_doc = await resolvers_config.did_resolver.resolve(_next)
        if next_did_doc is None:
            return False
        next_kids = next_did_doc.key_agreement_kids

    secret_ids = await resolvers_config.secrets_resolver.get_keys(next_kids)
    return len(secret_ids) > 0
