from typing import List

from authlib.common.encoding import (
    to_bytes,
    to_unicode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)
from authlib.jose import JsonWebEncryption

from didcomm.common.algorithms import AuthCryptAlg, Algs
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL, DIDCommMessageTypes
from didcomm.core.keys.authcrypt_keys_selector import (
    find_authcrypt_pack_sender_and_recipient_keys,
    find_authcrypt_unpack_sender_and_recipient_keys,
)
from didcomm.core.serialization import dict_to_json_bytes
from didcomm.core.types import EncryptResult, UnpackAuthcryptResult, Key
from didcomm.core.utils import extract_key, get_jwe_alg, calculate_apv
from didcomm.core.validation import validate_authcrypt_jwe
from didcomm.errors import MalformedMessageError, MalformedMessageCode


def is_authcrypted(msg: dict) -> bool:
    if "ciphertext" not in msg:
        return False
    alg = get_jwe_alg(msg)
    if alg is None:
        return False
    return alg.startswith("ECDH-1PU")


def authcrypt(msg: dict, to: List[Key], frm: Key, alg: AuthCryptAlg) -> EncryptResult:
    msg = dict_to_json_bytes(msg)

    skid = frm.kid
    kids = [to_key.kid for to_key in to]
    to_keys = [to_key.key for to_key in to]

    header_obj = _build_header(to=to, frm=frm, alg=alg)
    jwe = JsonWebEncryption()
    res = jwe.serialize_json(header_obj, msg, to_keys, sender_key=frm.key)

    return EncryptResult(msg=res, to_kids=kids, to_keys=to, from_kid=skid)


async def find_keys_and_authcrypt(
    msg: dict,
    to: DID_OR_DID_URL,
    frm: DID_OR_DID_URL,
    alg: AuthCryptAlg,
    resolvers_config: ResolversConfig,
) -> EncryptResult:
    pack_keys = await find_authcrypt_pack_sender_and_recipient_keys(
        frm, to, resolvers_config
    )
    frm_private_key = Key(
        kid=pack_keys.sender_private_key.kid,
        key=extract_key(pack_keys.sender_private_key),
    )
    to_public_keys = [
        Key(kid=to_key.id, key=extract_key(to_key))
        for to_key in pack_keys.recipient_public_keys
    ]
    return authcrypt(msg, to_public_keys, frm_private_key, alg)


async def unpack_authcrypt(
    msg: dict, resolvers_config: ResolversConfig, decrypt_by_all_keys: bool
) -> UnpackAuthcryptResult:
    protected = validate_authcrypt_jwe(msg)

    frm_kid = protected.get("skid")
    if frm_kid is None:
        frm_kid = to_unicode(urlsafe_b64decode(to_bytes(protected["apu"])))

    to_kids = [r["header"]["kid"] for r in msg["recipients"]]

    unpack_res = None
    async for unpack_keys in find_authcrypt_unpack_sender_and_recipient_keys(
        frm_kid, to_kids, resolvers_config
    ):
        frm_public_key = extract_key(unpack_keys.sender_public_key)
        to_private_kid_and_key = (
            unpack_keys.recipient_private_key.kid,
            extract_key(unpack_keys.recipient_private_key),
        )
        try:
            jwe = JsonWebEncryption()
            res = jwe.deserialize_json(
                msg, to_private_kid_and_key, sender_key=frm_public_key
            )
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
        alg = AuthCryptAlg(Algs(alg=protected["alg"], enc=protected["enc"]))

        unpack_res = UnpackAuthcryptResult(
            msg=res["payload"], to_kids=to_kids, frm_kid=frm_kid, alg=alg
        )
        if not decrypt_by_all_keys:
            return unpack_res

    if unpack_res is None:
        raise MalformedMessageError(MalformedMessageCode.CAN_NOT_DECRYPT)
    return unpack_res


def _build_header(to: List[Key], frm: Key, alg: AuthCryptAlg):
    skid = frm.kid
    kids = [to_key.kid for to_key in to]

    apu = to_unicode(urlsafe_b64encode(to_bytes(skid)))
    apv = calculate_apv(kids)
    protected = {
        "typ": DIDCommMessageTypes.ENCRYPTED.value,
        "alg": alg.value.alg,
        "enc": alg.value.enc,
        "apu": apu,
        "apv": apv,
        "skid": skid,
    }
    recipients = [{"header": {"kid": kid}} for kid in kids]
    return {"protected": protected, "recipients": recipients}
