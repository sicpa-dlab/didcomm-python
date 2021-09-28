from copy import copy

from authlib.common.encoding import to_unicode, to_bytes, json_loads, urlsafe_b64decode
from authlib.jose import JsonWebSignature

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JWT_TYPE, DID_URL
from didcomm.core.keys.sign_keys_selector import find_signing_key, find_verification_key
from didcomm.core.serialization import dict_to_json_bytes, json_bytes_to_dict
from didcomm.core.utils import extract_key, extract_sign_alg, is_did_url
from didcomm.errors import MalformedMessageError, MalformedMessageCode


async def pack_from_prior_field(message: dict, resolvers_config: ResolversConfig):
    if not message.get("from_prior"):
        return

    from_prior = message["from_prior"]
    if not isinstance(from_prior, dict):
        raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)
    if message.get("from") and from_prior["sub"] != message["from"]:
        raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

    jws = JsonWebSignature()

    iss_kid = from_prior["iss_kid"]
    from_prior = copy(from_prior)
    del from_prior["iss_kid"]

    payload = dict_to_json_bytes(from_prior)

    secret = await find_signing_key(iss_kid, resolvers_config)
    private_key = extract_key(secret)
    alg = extract_sign_alg(secret)

    protected = {"typ": JWT_TYPE, "alg": alg.value, "kid": iss_kid}

    packed = jws.serialize_compact(protected, payload, private_key)

    message["from_prior"] = to_unicode(packed)


async def unpack_from_prior_field(message: dict, resolvers_config: ResolversConfig):
    if not message.get("from_prior"):
        return

    packed_from_prior = message["from_prior"]
    if not isinstance(packed_from_prior, str):
        raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

    iss_kid = __extract_from_prior_kid(packed_from_prior)

    verification_method = await find_verification_key(iss_kid, resolvers_config)
    public_key = extract_key(verification_method)

    jws = JsonWebSignature()

    jws_object = jws.deserialize_compact(to_bytes(packed_from_prior), public_key)

    if jws_object.type != "compact":
        raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

    protected = jws_object.header.protected

    from_prior = json_bytes_to_dict(jws_object.payload)
    from_prior["iss_kid"] = protected["kid"]

    if message.get("from") and from_prior["sub"] != message["from"]:
        raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

    message["from_prior"] = from_prior


def __extract_from_prior_kid(packed_from_prior: str) -> DID_URL:
    packed_from_prior = to_bytes(packed_from_prior)
    protected_segment = packed_from_prior.split(b".")[0]
    protected = json_loads(urlsafe_b64decode(protected_segment).decode("utf-8"))
    if not is_did_url(protected.get("kid")):
        raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)
    return protected["kid"]
