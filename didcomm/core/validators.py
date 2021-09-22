import attr
from typing import Callable, Any, Optional
from packaging.specifiers import SpecifierSet
from urllib.parse import urlparse
from pathlib import Path

from didcomm.errors import DIDCommValueError
from didcomm.core.types import DIDCOMM_ORG_DOMAIN
from didcomm.core.utils import is_did, is_did_url, is_did_or_did_url


# TODO TEST
def _attr_validator_wrapper(attr_validator):
    def _f(instance, attribute, value):
        try:
            attr_validator(instance, attribute, value)
        except Exception as exc:
            raise DIDCommValueError(str(exc)) from exc

    return _f


# TODO TEST
def validator__instance_of(classinfo) -> Callable:
    return _attr_validator_wrapper(attr.validators.instance_of(classinfo))


# TODO TEST
def validator__in_(options) -> Callable:
    return _attr_validator_wrapper(attr.validators.in_(options))


# TODO TEST
def validator__deep_iterable(member_validator: Callable, iterable_validator=None):
    return _attr_validator_wrapper(
        attr.validators.deep_iterable(member_validator, iterable_validator)
    )


# TODO TEST
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
            raise DIDCommValueError(f"not a {DIDCOMM_ORG_DOMAIN} protocol: '{value}'")

        if not (
            path.parent.parent.name == p_name
            and path.parent.name in p_version_specifier
        ):
            raise DIDCommValueError(f"unexpected protocol in '{value}'")

        if path.name != p_msg_t:
            raise DIDCommValueError(f"unexpected message type in '{value}'")

    return _f


# TODO TEST
def validator__check_f(
    check_f: Callable[[Any], bool], error_msg: Optional[str] = "is unacceptable"
) -> Callable:
    def _f(instance, attribute, value):
        exc_msg = f"'{attribute.name}': value '{value}' {error_msg}"
        try:
            if not check_f(value):
                raise DIDCommValueError(exc_msg)
        except Exception as cause:
            raise DIDCommValueError(exc_msg) from cause

    return _f


# TODO TEST
def validator__did(instance, attribute, value) -> None:
    validator__check_f(is_did, "is not a did")(instance, attribute, value)


# TODO TEST
def validator__did_url(instance, attribute, value) -> None:
    validator__check_f(is_did_url, "is not a did url")(instance, attribute, value)


# TODO TEST
def validator__did_or_did_url(instance, attribute, value) -> None:
    validator__check_f(is_did_or_did_url, "is neither a did nor a did url")(
        instance, attribute, value
    )
