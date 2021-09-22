from authlib.common.encoding import json_loads, json_dumps, to_unicode, to_bytes, urlsafe_b64decode, urlsafe_b64encode


def update(msg, field, new_value):
    msg = json_loads(msg)
    msg[field] = new_value
    return json_dumps(msg)


def update_protected(msg, field, new_value):
    msg = json_loads(msg)
    protected = json_loads(to_unicode(urlsafe_b64decode(to_bytes(msg["protected"]))))
    protected[field] = new_value
    msg["protected"] = to_unicode(urlsafe_b64encode(to_bytes(json_dumps(protected))))
    return json_dumps(msg)
