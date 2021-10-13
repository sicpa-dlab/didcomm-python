from __future__ import annotations
from copy import deepcopy

import logging
import attr
from dataclasses import dataclass
from typing import List, Union, Optional, Callable, Dict
from packaging.specifiers import SpecifierSet
from enum import Enum

from didcomm.errors import (
    MalformedMessageError,
    MalformedMessageCode,
    DIDDocNotResolvedError,
    InvalidDIDDocError,
    DIDCommValueError,
)
from didcomm.common.types import (
    JSON,
    DID_OR_DID_URL,
    JSON_OBJ,
    DID_URL,
    DIDCommMessageProtocolTypes,
)
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.algorithms import AnonCryptAlg
from didcomm.message import GenericMessage, Header, Attachment, AttachmentDataJson
from didcomm.core.types import EncryptResult, DIDCommGeneratorType, DIDCOMM_ORG_DOMAIN
from didcomm.core.defaults import DEF_ENC_ALG_ANON
from didcomm.core.converters import converter__didcomm_id
from didcomm.core.validators import (
    validator__instance_of,
    validator__didcomm_protocol_mturi,
    validator__did_or_did_url,
)
from didcomm.core.serialization import (
    json_str_to_dict,
)
from didcomm.core.anoncrypt import find_keys_and_anoncrypt, unpack_anoncrypt
from didcomm.core.utils import get_did, is_did_or_did_url
from didcomm.did_doc.did_doc import DIDCommService


logger = logging.getLogger(__name__)


# TODO move to some ../routing/types.py
ROUTING_PROTOCOL_NAME = "routing"
ROUTING_PROTOCOL_VER_CURRENT = "2.0"
ROUTING_PROTOCOL_VER_COMPATIBILITY = SpecifierSet("~=2.0")


PROFILE_DIDCOMM_AIP1 = "didcomm/aip1"
PROFILE_DIDCOMM_AIP2_ENV_RFC19 = "didcomm/aip2;env=rfc19"
PROFILE_DIDCOMM_AIP2_ENV_RFC587 = "didcomm/aip2;env=rfc587"
PROFILE_DIDCOMM_V2 = "didcomm/v2"


class ROUTING_PROTOCOL_MSG_TYPES(Enum):
    FORWARD = "forward"


@attr.s(auto_attribs=True)
class ForwardBody:
    # TODO TEST
    next: DID_OR_DID_URL = attr.ib(
        validator=validator__did_or_did_url,
    )


@attr.s(auto_attribs=True)
class ForwardMessage(GenericMessage[ForwardBody]):
    # if not specified would be auto-generated
    id: Optional[Union[str, Callable]] = attr.ib(
        converter=converter__didcomm_id,
        validator=validator__instance_of(str),
        default=None,
    )
    type: Optional[str] = attr.ib(
        validator=[
            validator__instance_of(str),
            validator__didcomm_protocol_mturi(
                ROUTING_PROTOCOL_NAME,
                ROUTING_PROTOCOL_VER_COMPATIBILITY,
                ROUTING_PROTOCOL_MSG_TYPES.FORWARD.value,
            ),
        ],
        default=(
            f"https://{DIDCOMM_ORG_DOMAIN}"
            f"/{ROUTING_PROTOCOL_NAME}/{ROUTING_PROTOCOL_VER_CURRENT}"
            f"/{ROUTING_PROTOCOL_MSG_TYPES.FORWARD.value}"
        ),
    )
    attachments: List[Attachment] = attr.ib(kw_only=True)

    @attachments.validator
    def _check_attachments(self, attribute, value):
        if not (
            isinstance(value, list)
            and len(value) == 1
            and isinstance(value[0], Attachment)
            and isinstance(value[0].data, AttachmentDataJson)
            and isinstance(value[0].data.json, Dict)
        ):
            raise DIDCommValueError(f"'{attribute.name}': bad value '{value}'")

    @staticmethod
    def _body_from_dict(body: dict) -> ForwardBody:
        try:
            return ForwardBody(**body)
        except Exception as exc:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT) from exc

    @property
    def forwarded_msg(self) -> JSON_OBJ:
        """
        Unwrap (extract) forwarded message.

        :return: unwrapped message as JSON_OBJ
        """
        return self.attachments[0].data.json  # JSON_OBJ


@attr.s(auto_attribs=True)
class ForwardPackResult:
    msg: ForwardMessage
    msg_encrypted: EncryptResult


@dataclass
class ForwardResult:
    forward_msg: ForwardMessage
    forwarded_msg: JSON_OBJ
    forwarded_msg_encrypted_to: Optional[List[DID_URL]] = None


async def find_did_service(
    resolvers_config: ResolversConfig, to: DID_OR_DID_URL, service_id: str = None
) -> DIDCommService:

    to_did = get_did(to)
    did_doc = await resolvers_config.did_resolver.resolve(to_did)

    if did_doc is None:
        raise DIDDocNotResolvedError(to_did)

    if service_id:
        did_service = did_doc.get_didcomm_service(service_id)
        if did_service is None:
            # TODO define exc attrs instead of explicit message
            raise InvalidDIDDocError(
                f"service with service id '{service_id}' not found for DID '{to}'"
            )
        if PROFILE_DIDCOMM_V2 not in did_service.accept:
            raise InvalidDIDDocError(
                f"service with service id '{service_id}'"
                f" for DID '{to}' does not accept didcomm/v2 profile"
            )
        return did_service
    else:
        # Find the first service accepting `didcomm/v2` profile because the spec states:
        # > Entries SHOULD be specified in order of receiver preference,
        # > but any endpoint MAY be selected by the sender, typically
        # > by protocol availability or preference.
        # https://identity.foundation/didcomm-messaging/spec/#multiple-endpoints
        for did_service in did_doc.didcomm_services:
            if PROFILE_DIDCOMM_V2 in did_service.accept:
                return did_service
        return None


async def resolve_did_services_chain(
    resolvers_config: ResolversConfig,
    to: DID_OR_DID_URL,
    service_id: str = None,
    did_recursion=False,
) -> List[DIDCommService]:

    res = []

    to_did_service = await find_did_service(resolvers_config, to, service_id)
    if to_did_service is None:
        return res

    service_uri = to_did_service.service_endpoint
    res.insert(0, to_did_service)

    # alternative endpoints
    while is_did_or_did_url(service_uri):
        mediator_did = service_uri

        if len(res) > 1:
            # TODO cover possible case of alternative endpoints in mediator's
            #      DID Doc services (it SHOULD NOT be as per spec but ...)
            exc_t = NotImplementedError if did_recursion else InvalidDIDDocError
            raise exc_t(
                f"mediator '{res[-1].service_endpoint}' defines alternative"
                f" endpoint '{service_uri}' recursively"
            )

        # TODO check not only first item in mediator services list
        #      (e.g. first one may use alternative endpoint but second - URI)

        # resolve until final URI is reached
        mediator_did_service = await find_did_service(resolvers_config, mediator_did)
        if mediator_did_service is None:
            raise InvalidDIDDocError(f"mediator '{mediator_did}' service doc not found")

        service_uri = mediator_did_service.service_endpoint
        res.insert(0, mediator_did_service)

    return res


async def wrap_in_forward(
    resolvers_config: ResolversConfig,
    packed_msg: JSON_OBJ,
    to: DID_OR_DID_URL,
    routing_keys: List[DID_OR_DID_URL],
    enc_alg_anon: Optional[AnonCryptAlg] = DEF_ENC_ALG_ANON,
    headers: Optional[Header] = None,
    didcomm_id_generator: Optional[DIDCommGeneratorType] = None,
) -> Optional[ForwardPackResult]:
    """
    Resolves recipient DID DOC Service and Builds Forward envelops if needed.

    Wraps the given packed DIDComm message in Forward messages for every routing key.

    :param resolvers_config: secrets and DIDDoc resolvers
    :param packed_msg: the message to be wrapped in Forward messages
    :param to: recipient's DID (DID URL)
    :param routing_keys: list of routing keys
    :param enc_alg_anon (AnonCryptAlg): The encryption algorithm to be used for
        anonymous encryption (anon_crypt).
    :param headers: optional headers for Forward message
    :param didcomm_id_generator (Callable): optional callable to use
        for forward messages ``id`` generation, ``didcomm_id_generator_default``
        is used by default

    :raises DIDDocNotResolvedError: If a DID can not be resolved to a DID Doc.
    :raises DIDUrlNotFoundError: If a DID URL (for example a key ID) is not found within a DID Doc
    :raises SecretNotFoundError: If there is no secret for the given DID or DID URL (key ID)

    :return: a top-level packed Forward message as JSON string
    """

    headers = headers or {}  # TODO headers validation against ForwardMessage

    # means forward protocol is not needed
    if not routing_keys:
        logger.debug("No routing keys found: skipping forward wrapping")
        return None

    # wrap forward msgs in reversed order so the message to final
    # recipient 'to' will be the innermost one
    for _to, _next in zip(routing_keys[::-1], (routing_keys[1:] + [to])[::-1]):
        fwd_attach = Attachment(data=AttachmentDataJson(packed_msg))

        fwd_msg = ForwardMessage(
            id=didcomm_id_generator,
            body=ForwardBody(next=_next),
            type=DIDCommMessageProtocolTypes.FORWARD.value,
            attachments=[fwd_attach],
            **headers,
        )

        fwd_msg_encrypted = await find_keys_and_anoncrypt(
            fwd_msg.as_dict(), _to, enc_alg_anon, resolvers_config
        )

        packed_msg = fwd_msg_encrypted.msg

    logger.debug(f"forward wrapping result: {fwd_msg_encrypted.msg}")

    return ForwardPackResult(fwd_msg, fwd_msg_encrypted)


async def unpack_forward(
    resolvers_config: ResolversConfig,
    packed_msg: Union[JSON, JSON_OBJ],
    decrypt_by_all_keys: bool,
) -> ForwardResult:
    """
    Can be called by a Mediator who expects a Forward message to be unpacked

    :param resolvers_config: secrets and DIDDoc resolvers
    :param packed_msg: a Forward message as JSON string to be unpacked

    :raises DIDDocNotResolvedError: If a DID can not be resolved to a DID Doc.
    :raises DIDUrlNotFoundError: If a DID URL (for example a key ID) is not found within a DID Doc
    :raises DIDCommValueError: invalid type of packed message
    :raises SecretNotFoundError: If there is no secret for the given DID or DID URL (key ID)
    :raises MalformedMessageError: if the message is invalid (can not be decrypted, signature is invalid, the plaintext is invalid, etc.)

    :return: Forward plaintext
    """
    if isinstance(packed_msg, str):
        msg_as_dict = json_str_to_dict(packed_msg)
    elif isinstance(packed_msg, dict):
        msg_as_dict = packed_msg
    else:
        # FIXME in python it should be a kind of TypeError instead
        raise DIDCommValueError(
            f"unexpected type of packed_message: '{type(packed_msg)}'"
        )

    fwd_unpack_res = await unpack_anoncrypt(
        msg_as_dict, resolvers_config, decrypt_by_all_keys
    )

    try:
        fwd_msg = ForwardMessage.from_json(fwd_unpack_res.msg)
    except DIDCommValueError as exc:
        raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT) from exc

    forwarded_msg_dict = fwd_msg.forwarded_msg

    logger.debug(
        f"unpacked Forward: forwarded msg {forwarded_msg_dict}, to_kids"
        f" {fwd_unpack_res.to_kids}"
    )

    return ForwardResult(
        forward_msg=fwd_msg,
        forwarded_msg=forwarded_msg_dict,
        forwarded_msg_encrypted_to=fwd_unpack_res.to_kids,
    )


# TODO CONSIDER forward validation might be a part of ForwardMessage
def is_forward(msg: Union[dict, JSON, bytes]) -> bool:
    """
    A helper method to check if the given message is a Forward message.

    :param message: the message to be checked
    :return: True if the plaintext is a valid Forward message and false otherwise
    """
    try:
        (
            ForwardMessage.from_dict(deepcopy(msg))
            if isinstance(msg, dict)
            else ForwardMessage.from_json(msg)
        )
    except Exception:
        return False
    else:
        return True
