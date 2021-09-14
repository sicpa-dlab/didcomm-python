import attr
from typing import Callable
from packaging.specifiers import SpecifierSet
from urllib.parse import urlparse
from pathlib import Path

from didcomm.errors import DIDCommValueError
from didcomm.core.types import DIDCOMM_ORG_DOMAIN


def validator__instance_of(classinfo) -> Callable:

    def _f(instance, attribute, value):
        try:
            attr.validators.instance_of(classinfo)(instance, attribute, value)
        except TypeError as exc:
            raise DIDCommValueError(str(exc)) from exc

    return _f


def validator__didcomm_protocol_mturi(
    p_name: str, p_version_specifier: SpecifierSet, p_msg_t: str
) -> Callable:

    # TODO strict check as per
    #      https://github.com/hyperledger/aries-rfcs/blob/main/concepts/0003-protocols/README.md#mturi
    def _f(instance, attribute, value):
        parsed = urlparse(value)
        path = Path(parsed.path)

        if not (
            parsed.scheme == "https"
            and parsed.netloc == DIDCOMM_ORG_DOMAIN
            # e.g. ('/', 'routing', '2.0.0', 'forward')
            and len(path.parts) == 4
        ):
            raise DIDCommValueError(
                f"not a {DIDCOMM_ORG_DOMAIN} protocol: '{value}'"
            )

        if not (
            path.parent.parent.name == p_name
            and path.parent.name in p_version_specifier
        ):
            raise DIDCommValueError(f"unexpected protocol in '{value}'")

        if path.name != p_msg_t:
            raise DIDCommValueError(f"unexpected message type in '{value}'")

    return _f
