from authlib.common.encoding import to_bytes, urlsafe_b64decode, to_unicode

from didcomm.core.utils import is_did_url, parse_base64url_encoded_json, calculate_apv
from didcomm.errors import MalformedMessageError, MalformedMessageCode


def validate_jws(msg: dict):
    if (
        "signatures" not in msg
        or not msg["signatures"]
        or "header" not in msg["signatures"][0]
        or "kid" not in msg["signatures"][0]["header"]
    ):
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)


def validate_anoncrypt_jwe(msg: dict):
    # 1. Validate recipient unprotected header
    if "recipients" not in msg:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)
    for r in msg["recipients"]:
        if "header" not in r or "kid" not in r["header"]:
            raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)

    # 2. Decode protected header
    protected_header = _get_protected_header(msg)

    # 3. Check apv
    _check_apv(protected_header, msg["recipients"])

    return protected_header


def validate_authcrypt_jwe(msg: dict):
    # 1. Validate recipient unprotected header
    if "recipients" not in msg:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)
    for r in msg["recipients"]:
        if "header" not in r or "kid" not in r["header"]:
            raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)
        if not is_did_url(r["header"]["kid"]):
            raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)

    # 2. Decode protected header
    protected_header = _get_protected_header(msg)

    # 3. Check apu
    if "apu" not in protected_header:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)
    try:
        apu = to_unicode(urlsafe_b64decode(to_bytes(protected_header["apu"])))
    except Exception as exc:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE) from exc
    if not is_did_url(apu):
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)

    # 4. Check skid
    if "skid" in protected_header and protected_header["skid"] != apu:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)

    # 5. Check apv
    _check_apv(protected_header, msg["recipients"])

    return protected_header


def _get_protected_header(jwe: dict):
    if "protected" not in jwe:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)
    try:
        protected = parse_base64url_encoded_json(jwe["protected"])
    except Exception as exc:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE) from exc
    return protected


def _check_apv(protected_header: dict, recipients: list):
    if "apv" not in protected_header:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)
    kids = [r["header"]["kid"] for r in recipients]
    expected_apv = calculate_apv(kids)
    if protected_header["apv"] != expected_apv:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)
