from dataclasses import dataclass
from typing import List

from authlib.common.encoding import to_bytes, to_unicode, urlsafe_b64encode, json_dumps
from authlib.jose import JsonWebEncryption

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL
from didcomm.common.utils import find_key_agreement_secret_and_verification_methods, extract_key
from didcomm.pack_encrypted import PackEncryptedConfig


@dataclass(frozen=True)
class AuthcryptResult:
    msg: bytes
    to_kids: List[DID_OR_DID_URL]
    from_kid: DID_OR_DID_URL


async def authcrypt(msg: bytes,
                    to: DID_OR_DID_URL,
                    frm: DID_OR_DID_URL,
                    pack_config: PackEncryptedConfig,
                    resolvers_config: ResolversConfig) -> AuthcryptResult:

    jwe = JsonWebEncryption()

    frm_secret, to_verification_methods = \
        find_key_agreement_secret_and_verification_methods(frm, to, resolvers_config)
    frm_private_key = extract_key(frm_secret)
    to_public_keys = [extract_key(to_vm) for to_vm in to_verification_methods]

    skid = frm_private_key.kid
    kids = [to_vm.id for to_vm in to_verification_methods]

    apu = to_unicode(urlsafe_b64encode(to_bytes(skid)))
    apv = to_unicode(urlsafe_b64encode(to_bytes('.'.join(sorted(kids)))))

    protected = {
        "typ": "application/didcomm-encrypted+json",
        "alg": pack_config.enc_alg_auth.value.alg,
        "enc": pack_config.enc_alg_auth.value.enc,
        "apu": apu,
        "apv": apv,
        "skid": skid
    }

    recipients = [{"header": {"kid": kid}} for kid in kids]

    header_obj = {
        "protected": protected,
        "recipients": recipients
    }

    msg = jwe.serialize_json(header_obj, msg, to_public_keys, sender_key=frm_private_key)

    return AuthcryptResult(
        msg=to_bytes(json_dumps(msg)),
        to_kids=kids,
        from_kid=skid
    )
