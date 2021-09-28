from authlib.common.encoding import to_bytes, json_dumps, json_loads, to_unicode

from didcomm.common.types import JSON
from didcomm.errors import MalformedMessageError, MalformedMessageCode


def dict_to_json_bytes(msg: dict) -> bytes:
    return to_bytes(json_dumps(msg))


def dict_to_json(msg: dict) -> JSON:
    return json_dumps(msg)


def json_bytes_to_dict(json_bytes: bytes) -> dict:
    return json_str_to_dict(to_unicode(json_bytes))


def json_str_to_dict(json_str: JSON) -> dict:
    try:
        json_dict = json_loads(json_str)
    except Exception as exc:
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE) from exc

    if not isinstance(json_dict, dict):  # in case of a primitive value
        raise MalformedMessageError(MalformedMessageCode.INVALID_MESSAGE)

    return json_dict
