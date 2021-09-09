from authlib.common.encoding import json_loads, json_dumps


def update(msg, field, new_value):
    msg = json_loads(msg)
    msg[field] = new_value
    return json_dumps(msg)
