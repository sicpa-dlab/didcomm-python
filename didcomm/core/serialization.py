from authlib.common.encoding import to_bytes, json_dumps, json_loads, to_unicode

from didcomm.common.types import JSON
from didcomm.errors import MalformedMessageError, MalformedMessageCode


def dict_to_json_bytes(msg: dict) -> bytes:
    return to_bytes(json_dumps(msg))


def dict_to_json(msg: dict) -> JSON:
    return json_dumps(msg)


def json_bytes_to_dict(json_bytes: bytes) -> dict:
    try:
        return json_loads(to_unicode(json_bytes))
    except Exception as exc:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE) from exc


def json_str_to_dict(json_str: JSON) -> dict:
    try:
        return json_loads(json_str)
    except Exception as exc:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE) from exc
