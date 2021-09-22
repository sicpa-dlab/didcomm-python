from typing import List

from authlib.jose import JsonWebEncryption

from didcomm.common.algorithms import AnonCryptAlg, Algs
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL, DIDCommMessageTypes
from didcomm.core.keys.anoncrypt_keys_selector import (
    find_anoncrypt_pack_recipient_public_keys,
    find_anoncrypt_unpack_recipient_private_keys,
)
from didcomm.core.serialization import dict_to_json_bytes
from didcomm.core.types import EncryptResult, UnpackAnoncryptResult, Key
from didcomm.core.utils import extract_key, get_jwe_alg, calculate_apv
from didcomm.core.validation import validate_anoncrypt_jwe
from didcomm.errors import MalformedMessageError, MalformedMessageCode


def is_anoncrypted(msg: dict) -> bool:
    if "ciphertext" not in msg:
        return False
    alg = get_jwe_alg(msg)
    if alg is None:
        return False
    return alg.startswith("ECDH-ES")


def anoncrypt(msg: dict, to: List[Key], alg: AnonCryptAlg) -> EncryptResult:
    msg = dict_to_json_bytes(msg)

    kids = [to_key.kid for to_key in to]
    keys = [to_key.key for to_key in to]

    header_obj = _build_header(to=to, alg=alg)

    jwe = JsonWebEncryption()
    res = jwe.serialize_json(header_obj, msg, keys)

    return EncryptResult(msg=res, to_kids=kids, to_keys=to)


async def find_keys_and_anoncrypt(
    msg: dict, to: DID_OR_DID_URL, alg: AnonCryptAlg, resolvers_config: ResolversConfig
) -> EncryptResult:
    to_verification_methods = await find_anoncrypt_pack_recipient_public_keys(
        to, resolvers_config
    )
    to_public_keys = [
        Key(kid=to_vm.id, key=extract_key(to_vm)) for to_vm in to_verification_methods
    ]
    return anoncrypt(msg, to_public_keys, alg)


async def unpack_anoncrypt(
    msg: dict, resolvers_config: ResolversConfig, decrypt_by_all_keys: bool
) -> UnpackAnoncryptResult:
    validate_anoncrypt_jwe(msg)

    to_kids = [r["header"]["kid"] for r in msg["recipients"]]

    unpack_res = None
    async for to_secret in find_anoncrypt_unpack_recipient_private_keys(
        to_kids, resolvers_config
    ):
        to_private_kid_and_key = (to_secret.kid, extract_key(to_secret))
        try:
            jwe = JsonWebEncryption()
            res = jwe.deserialize_json(msg, to_private_kid_and_key)
        except Exception as exc:
            if decrypt_by_all_keys:
                raise MalformedMessageError(
                    MalformedMessageCode.CAN_NOT_DECRYPT
                ) from exc
            continue

        if "payload" not in res:
            raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)
        if "header" not in res or "protected" not in res["header"]:
            raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)
        protected = res["header"]["protected"]
        if "alg" not in protected or "enc" not in protected:
            raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)
        alg = AnonCryptAlg(Algs(alg=protected["alg"], enc=protected["enc"]))

        unpack_res = UnpackAnoncryptResult(msg=res["payload"], to_kids=to_kids, alg=alg)
        if not decrypt_by_all_keys:
            return unpack_res

    if unpack_res is None:
        raise MalformedMessageError(MalformedMessageCode.CAN_NOT_DECRYPT)
    return unpack_res


def _build_header(to: List[Key], alg: AnonCryptAlg):
    kids = [to_key.kid for to_key in to]
    apv = calculate_apv(kids)
    protected = {
        "typ": DIDCommMessageTypes.ENCRYPTED.value,
        "alg": alg.value.alg,
        "enc": alg.value.enc,
        "apv": apv,
    }
    recipients = [{"header": {"kid": kid}} for kid in kids]
    return {"protected": protected, "recipients": recipients}
