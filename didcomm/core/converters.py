from typing import Optional, Union, Any, Callable

from didcomm.core.utils import id_generator_default, didcomm_id_generator_default


def converter__id(_id: Optional[Union[Any, Callable]] = None):
    if _id is None:
        return id_generator_default()
    elif callable(_id):
        return _id()
    else:
        return _id


def converter__didcomm_id(didcomm_id: Optional[Union[Any, Callable]] = None):
    if didcomm_id is None:
        return didcomm_id_generator_default()
    else:
        return converter__id(didcomm_id)
