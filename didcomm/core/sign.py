from authlib.jose import JsonWebSignature
from authlib.jose.errors import BadSignatureError

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL, DIDCommMessageTypes
from didcomm.core.keys.sign_keys_selector import find_signing_key, find_verification_key
from didcomm.core.serialization import dict_to_json_bytes
from didcomm.core.types import SignResult, UnpackSignResult
from didcomm.core.utils import extract_key, extract_sign_alg
from didcomm.core.validation import validate_jws
from didcomm.errors import MalformedMessageError, MalformedMessageCode


def is_signed(msg: dict) -> bool:
    return "payload" in msg


async def sign(
    msg: dict, sign_frm: DID_OR_DID_URL, resolvers_config: ResolversConfig
) -> SignResult:
    msg = dict_to_json_bytes(msg)

    jws = JsonWebSignature()

    secret = await find_signing_key(sign_frm, resolvers_config)
    private_key = extract_key(secret)
    alg = extract_sign_alg(secret)

    protected = {"typ": DIDCommMessageTypes.SIGNED.value, "alg": alg.value}

    header = {"kid": secret.kid}

    header_objs = [{"protected": protected, "header": header}]

    res = jws.serialize_json(header_objs, msg, private_key)

    return SignResult(msg=res, sign_frm_kid=secret.kid)


async def unpack_sign(msg: dict, resolvers_config: ResolversConfig) -> UnpackSignResult:
    validate_jws(msg)

    sign_frm_kid = msg["signatures"][0]["header"]["kid"]
    sign_frm_verification_method = await find_verification_key(
        sign_frm_kid, resolvers_config
    )
    public_key = extract_key(sign_frm_verification_method)
    alg = extract_sign_alg(sign_frm_verification_method)

    try:
        jws = JsonWebSignature()
        jws_object = jws.deserialize_json(msg, public_key)
    except BadSignatureError as exc:
        raise MalformedMessageError(MalformedMessageCode.INVALID_SIGNATURE) from exc
    except Exception as exc:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE) from exc

    return UnpackSignResult(msg=jws_object.payload, sign_frm_kid=sign_frm_kid, alg=alg)
