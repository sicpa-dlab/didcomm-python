from dataclasses import dataclass
from typing import List

from authlib.common.encoding import to_bytes, to_unicode, urlsafe_b64encode, json_dumps, urlsafe_b64decode
from authlib.jose import JsonWebEncryption

from didcomm.common.algorithms import AuthCryptAlg, Algs
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_OR_DID_URL, DID_URL
from didcomm.common.utils import find_key_agreement_secret_and_verification_methods, extract_key, \
    find_key_agreement_sender_verification_method, find_key_agreement_recipient_secrets, parse_base64url_encoded_json
from didcomm.errors import MalformedMessageError, MalformedMessageCode


@dataclass(frozen=True)
class AuthcryptResult:
    msg: bytes
    to_kids: List[DID_OR_DID_URL]
    from_kid: DID_OR_DID_URL


async def authcrypt(msg: bytes,
                    to: DID_OR_DID_URL,
                    frm: DID_OR_DID_URL,
                    alg: AuthCryptAlg,
                    resolvers_config: ResolversConfig) -> AuthcryptResult:

    jwe = JsonWebEncryption()

    frm_secret, to_verification_methods = \
        await find_key_agreement_secret_and_verification_methods(frm, to, resolvers_config)
    frm_private_key = extract_key(frm_secret)
    to_public_keys = [extract_key(to_vm) for to_vm in to_verification_methods]

    skid = frm_secret.kid
    kids = [to_vm.id for to_vm in to_verification_methods]

    apu = to_unicode(urlsafe_b64encode(to_bytes(skid)))
    apv = to_unicode(urlsafe_b64encode(to_bytes('.'.join(sorted(kids)))))

    protected = {
        "typ": "application/didcomm-encrypted+json",
        "alg": alg.value.alg,
        "enc": alg.value.enc,
        "apu": apu,
        "apv": apv,
        "skid": skid
    }

    recipients = [{"header": {"kid": kid}} for kid in kids]

    header_obj = {
        "protected": protected,
        "recipients": recipients
    }

    res = jwe.serialize_json(header_obj, msg, to_public_keys, sender_key=frm_private_key)

    return AuthcryptResult(
        msg=to_bytes(json_dumps(res)),
        to_kids=kids,
        from_kid=skid
    )


@dataclass(frozen=True)
class UnwrapAuthcryptResult:
    msg: bytes
    to_kids: List[DID_URL]
    frm_kid: DID_URL
    alg: AuthCryptAlg


async def unwrap_authcrypt(msg: dict,
                           resolvers_config: ResolversConfig) -> UnwrapAuthcryptResult:

    jwe = JsonWebEncryption()

    protected = parse_base64url_encoded_json(msg['protected'])
    frm_kid = protected.get('skid')
    if frm_kid is None:
        frm_kid = to_unicode(urlsafe_b64decode(to_bytes(protected['apu'])))

    to_kids = [r['header']['kid'] for r in msg['recipients']]
    # FIXME: Add checks of "apu" (unconditional) and "apv" header fields

    frm_verification_method = await find_key_agreement_sender_verification_method(frm_kid, resolvers_config)
    to_secrets = await find_key_agreement_recipient_secrets(to_kids, resolvers_config)

    frm_public_key = extract_key(frm_verification_method)
    to_private_kids_and_keys = [(to_s.kid, extract_key(to_s)) for to_s in to_secrets]

    error = None
    for to_private_kid_and_key in to_private_kids_and_keys:
        try:
            res = jwe.deserialize_json(msg, to_private_kid_and_key, sender_key=frm_public_key)
            protected = res['header']['protected']
            alg = AuthCryptAlg(Algs(alg=protected['alg'], enc=protected['enc']))

            # FIXME: Support `expect_decrypt_by_all_keys` flag
            return UnwrapAuthcryptResult(
                msg=res['payload'],
                to_kids=to_kids,
                frm_kid=frm_kid,
                alg=alg
            )
        except Exception:
            error = MalformedMessageError(MalformedMessageCode.CAN_NOT_DECRYPT)
            continue

    raise error
