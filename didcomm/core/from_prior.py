from typing import Optional

from authlib.common.encoding import to_unicode, to_bytes, json_loads, urlsafe_b64decode
from authlib.jose import JsonWebToken
from authlib.jose.errors import BadSignatureError

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID_URL
from didcomm.core.keys.sign_keys_selector import find_signing_key, find_verification_key
from didcomm.core.utils import extract_key, extract_sign_alg, is_did_url, get_did
from didcomm.errors import (
    MalformedMessageError,
    MalformedMessageCode,
    DIDCommValueError,
)


async def pack_from_prior_in_place(
    message: dict, resolvers_config: ResolversConfig, issuer_kid: Optional[DID_URL]
) -> Optional[DID_URL]:
    """
    Packs from_prior field within a given message to JWT (compactly serialized JWS with claim set)
    if the message contains from_prior.
    In result, the message will contain the packed from_prior.

    Args:
        message: a plaintext message as a dict which optionally contains from_prior not yet packed to JWS
        resolvers_config: secrets and DIDDoc resolvers
        issuer_kid: optionally provided issuer key to use for signing from_prior

    Returns:
        identifier of the issuer key actually used to sign from_prior if the latter is present
    """
    if message.get("from_prior") is None:
        return None

    from_prior = message["from_prior"]

    if not isinstance(from_prior, dict):
        raise MalformedMessageError(
            MalformedMessageCode.INVALID_PLAINTEXT, "from_prior plaintext is invalid"
        )

    if from_prior["sub"] == from_prior["iss"]:
        raise DIDCommValueError(
            f"from_prior `iss` and `sub` values must not be equal but got from_prior value: {from_prior}"
        )

    if message.get("from") is not None and from_prior["sub"] != message["from"]:
        raise DIDCommValueError(
            f"from_prior `sub` value {from_prior['sub']} is not equal to message `from` value {message['from']}"
        )

    if issuer_kid is not None and get_did(issuer_kid) != from_prior["iss"]:
        raise DIDCommValueError(
            f"Provided issuer_kid {issuer_kid} does not belong to from_prior `iss` {from_prior['iss']}"
        )

    issuer_did_or_kid = issuer_kid or from_prior["iss"]

    jwt = JsonWebToken()

    secret = await find_signing_key(issuer_did_or_kid, resolvers_config)
    private_key = extract_key(
        secret, align_kid=True
    )  # kid within key must have proper value because JsonWebToken.encode writes its value to JWT's header kid field
    alg = extract_sign_alg(secret)

    header = {"alg": alg.value}

    message["from_prior"] = to_unicode(jwt.encode(header, from_prior, private_key))

    return secret.kid


async def unpack_from_prior_in_place(
    message: dict, resolvers_config: ResolversConfig
) -> Optional[DID_URL]:
    """
    Unpacks from_prior field within a given message from JWT (compactly serialized JWS with claim set)
    if the message contains from_prior.
    In result, the message will contain the unpacked from_prior.

    Args:
        message: a plaintext message as a dict which optionally contains from_prior packed to JWS
        resolvers_config: secrets and DIDDoc resolvers

    Returns:
        identifier of the issuer key which from_prior was signed with if the latter is present
    """
    if message.get("from_prior") is None:
        return None

    from_prior_jwt = message["from_prior"]

    if not isinstance(from_prior_jwt, str):
        raise MalformedMessageError(
            MalformedMessageCode.INVALID_MESSAGE, "from_prior value is invalid"
        )

    issuer_kid = __extract_from_prior_kid(from_prior_jwt)

    verification_method = await find_verification_key(issuer_kid, resolvers_config)
    public_key = extract_key(verification_method)

    try:
        jwt = JsonWebToken()
        message["from_prior"] = jwt.decode(to_bytes(from_prior_jwt), public_key)
    except BadSignatureError as exc:
        raise MalformedMessageError(
            MalformedMessageCode.INVALID_SIGNATURE,
            "from_prior signature is invalid",
        ) from exc
    except Exception as exc:
        raise MalformedMessageError(
            MalformedMessageCode.INVALID_MESSAGE, "from_prior value is invalid"
        ) from exc

    return issuer_kid


def __extract_from_prior_kid(from_prior_jwt: str) -> DID_URL:
    try:
        from_prior_jwt = to_bytes(from_prior_jwt)
        protected_segment = from_prior_jwt.split(b".")[0]
        protected = json_loads(urlsafe_b64decode(protected_segment).decode("utf-8"))
        if not is_did_url(protected.get("kid")):
            raise DIDCommValueError(
                f"from_prior `kid` value is not a valid DID URL: {protected.get('kid')}"
            )
        return protected["kid"]
    except Exception as exc:
        raise MalformedMessageError(
            MalformedMessageCode.INVALID_MESSAGE, "from_prior value is invalid"
        ) from exc
