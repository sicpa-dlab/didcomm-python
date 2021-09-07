from dataclasses import dataclass
from typing import List

from authlib.common.encoding import to_bytes, to_unicode, urlsafe_b64encode, json_dumps
from authlib.jose import JsonWebEncryption

from didcomm.common.algorithms import AnonCryptAlg, Algs
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL, DID_URL
from didcomm.common.utils import (
    extract_key,
    find_key_agreement_recipient_secrets,
    find_key_agreement_recipient_verification_methods,
)
from didcomm.errors import MalformedMessageError, MalformedMessageCode


@dataclass(frozen=True)
class AnoncryptResult:
    msg: bytes
    to_kids: List[DID_OR_DID_URL]


async def anoncrypt(
    msg: bytes, to: DID_OR_DID_URL, alg: AnonCryptAlg, resolvers_config: ResolversConfig
) -> AnoncryptResult:
    jwe = JsonWebEncryption()

    to_verification_methods = await find_key_agreement_recipient_verification_methods(
        to, resolvers_config
    )
    to_public_keys = [extract_key(to_vm) for to_vm in to_verification_methods]

    kids = [to_vm.id for to_vm in to_verification_methods]

    apv = to_unicode(urlsafe_b64encode(to_bytes(".".join(sorted(kids)))))

    protected = {
        "typ": "application/didcomm-encrypted+json",
        "alg": alg.value.alg,
        "enc": alg.value.enc,
        "apv": apv,
    }

    recipients = [{"header": {"kid": kid}} for kid in kids]

    header_obj = {"protected": protected, "recipients": recipients}

    res = jwe.serialize_json(header_obj, msg, to_public_keys)

    return AnoncryptResult(msg=to_bytes(json_dumps(res)), to_kids=kids)


@dataclass(frozen=True)
class UnwrapAnoncryptResult:
    msg: bytes
    to_kids: List[DID_URL]
    alg: AnonCryptAlg


async def unwrap_anoncrypt(
    msg: dict, resolvers_config: ResolversConfig
) -> UnwrapAnoncryptResult:
    jwe = JsonWebEncryption()

    to_kids = [r["header"]["kid"] for r in msg["recipients"]]
    # FIXME: Add check "apv" header field

    to_secrets = await find_key_agreement_recipient_secrets(to_kids, resolvers_config)

    to_private_kids_and_keys = [(to_s.kid, extract_key(to_s)) for to_s in to_secrets]

    for to_private_kid_and_key in to_private_kids_and_keys:
        try:
            res = jwe.deserialize_json(msg, to_private_kid_and_key)
            protected = res["header"]["protected"]
            alg = AnonCryptAlg(Algs(alg=protected["alg"], enc=protected["enc"]))

            # FIXME: Support `expect_decrypt_by_all_keys` flag
            return UnwrapAnoncryptResult(msg=res["payload"], to_kids=to_kids, alg=alg)
        except Exception as exc:
            raise MalformedMessageError(MalformedMessageCode.CAN_NOT_DECRYPT) from exc
