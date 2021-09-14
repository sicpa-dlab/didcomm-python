import attr

from didcomm.errors import DIDCommValueError


def validator__instance_of(classinfo):

    def _f(instance, attribute, value):
        try:
            attr.validators.instance_of(classinfo)(instance, attribute, value)
        except TypeError as exc:
            raise DIDCommValueError()

    return _f
