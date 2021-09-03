from dataclasses import dataclass

from authlib.common.encoding import json_dumps, to_bytes
from authlib.jose import JsonWebSignature
from authlib.jose.errors import BadSignatureError

from didcomm.common.algorithms import SignAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL, DID_URL
from didcomm.common.utils import find_authentication_secret, extract_key, extract_sign_alg, \
    find_authentication_verification_method
from didcomm.errors import MalformedMessageError, MalformedMessageCode


@dataclass(frozen=True)
class SignResult:
    msg: bytes
    sign_from_kid: DID_URL


async def sign(msg: bytes,
               sign_frm: DID_OR_DID_URL,
               resolvers_config: ResolversConfig) -> SignResult:

    jws = JsonWebSignature()

    secret = await find_authentication_secret(sign_frm, resolvers_config)
    private_key = extract_key(secret)
    alg = extract_sign_alg(secret)

    protected = {
        "typ": "application/didcomm-signed+json",
        "alg": alg.value
    }

    header = {
        "kid": secret.kid
    }

    header_objs = [{
        "protected": protected,
        "header": header
    }]

    msg = jws.serialize_json(header_objs, msg, private_key)

    return SignResult(
        msg=to_bytes(json_dumps(msg)),
        sign_from_kid=secret.kid
    )


@dataclass(frozen=True)
class UnwrapSignResult:
    msg: bytes
    sign_frm_kid: DID_URL
    sign_alg: SignAlg


async def unwrap_sign(msg: dict,
                      resolvers_config: ResolversConfig) -> UnwrapSignResult:

    jws = JsonWebSignature()

    sign_frm_kid = msg['signatures'][0]['header']['kid']

    sign_frm_verification_method = await find_authentication_verification_method(sign_frm_kid, resolvers_config)

    public_key = extract_key(sign_frm_verification_method)
    alg = extract_sign_alg(sign_frm_verification_method)

    try:
        jws_object = jws.deserialize_json(msg, public_key)
    except BadSignatureError:
        raise MalformedMessageError(MalformedMessageCode.INVALID_SIGNATURE)

    return UnwrapSignResult(
        msg=jws_object.payload,
        sign_frm_kid=sign_frm_kid,
        sign_alg=alg
    )
