from typing import Optional

from authlib.common.encoding import to_unicode, to_bytes, json_loads, urlsafe_b64decode
from authlib.jose import JsonWebSignature
from authlib.jose.errors import BadSignatureError

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JWT_TYPE, DID_URL
from didcomm.core.keys.sign_keys_selector import find_signing_key, find_verification_key
from didcomm.core.serialization import dict_to_json_bytes, json_bytes_to_dict
from didcomm.core.utils import extract_key, extract_sign_alg, is_did_url, get_did
from didcomm.errors import (
    MalformedMessageError,
    MalformedMessageCode,
    DIDCommValueError,
)


async def pack_from_prior_in_place(
    message: dict, resolvers_config: ResolversConfig, issuer_kid: Optional[DID_URL]
) -> DID_URL:
    """
    Packs from_prior field within a given message to JWS (if the message contains from_prior).
    In result, the message will contain the packed from_prior.

    Args:
        message: a plaintext message as a dict which optionally contains from_prior not yet packed to JWS
        resolvers_config: secrets and DIDDoc resolvers
        issuer_kid: optionally provided issuer key to use for signing from_prior

    Returns:
        identifier of the issuer key actually used to sign from_prior
    """
    if message.get("from_prior") is None:
        return None

    from_prior = message["from_prior"]

    if not isinstance(from_prior, dict):
        raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

    if issuer_kid is not None and get_did(issuer_kid) != from_prior["iss"]:
        raise DIDCommValueError()

    issuer_did_or_kid = issuer_kid or from_prior["iss"]

    jws = JsonWebSignature()

    payload = dict_to_json_bytes(from_prior)

    secret = await find_signing_key(issuer_did_or_kid, resolvers_config)
    private_key = extract_key(secret)
    alg = extract_sign_alg(secret)

    protected = {"typ": JWT_TYPE, "alg": alg.value, "kid": secret.kid}

    message["from_prior"] = to_unicode(
        jws.serialize_compact(protected, payload, private_key)
    )

    return secret.kid


async def unpack_from_prior_in_place(
    message: dict, resolvers_config: ResolversConfig
) -> DID_URL:
    """
    Unpacks from_prior field within a given message from JWS (if the message contains from_prior).
    In result, the message will contain the unpacked from_prior.

    Args:
        message: a plaintext message as a dict which optionally contains from_prior packed to JWS
        resolvers_config: secrets and DIDDoc resolvers

    Returns:
        identifier of the issuer key which from_prior was signed with
    """
    if message.get("from_prior") is None:
        return None

    packed_from_prior = message["from_prior"]

    if not isinstance(packed_from_prior, str):
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)

    issuer_kid = __extract_from_prior_kid(packed_from_prior)

    verification_method = await find_verification_key(issuer_kid, resolvers_config)
    public_key = extract_key(verification_method)

    try:
        jws = JsonWebSignature()
        jws_object = jws.deserialize_compact(to_bytes(packed_from_prior), public_key)
    except BadSignatureError as exc:
        raise MalformedMessageError(MalformedMessageCode.INVALID_SIGNATURE) from exc
    except Exception as exc:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE) from exc

    if jws_object.type != "compact":
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)

    protected = jws_object.header.protected
    if protected.get("typ") != JWT_TYPE:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)

    message["from_prior"] = json_bytes_to_dict(jws_object.payload)

    return issuer_kid


def __extract_from_prior_kid(packed_from_prior: str) -> DID_URL:
    packed_from_prior = to_bytes(packed_from_prior)
    protected_segment = packed_from_prior.split(b".")[0]
    protected = json_loads(urlsafe_b64decode(protected_segment).decode("utf-8"))
    if not is_did_url(protected.get("kid")):
        raise DIDCommValueError()
    return protected["kid"]
