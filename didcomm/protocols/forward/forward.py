from __future__ import annotations

import logging
import attr
from dataclasses import dataclass
from typing import List, Union, Optional, Callable

from didcomm.errors import (
    MalformedMessageError,
    MalformedMessageCode,
    DIDDocNotResolvedError,
    InvalidDIDDocError
)
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.algorithms import AnonCryptAlg
from didcomm.common.types import (
    JSON,
    DID_OR_DID_URL,
    JSON_OBJ, DID_URL,
    DIDCommMessageProtocolTypes,
)
from didcomm.message import (
    GenericMessage,
    Header,
    Attachment,
    AttachmentDataJson
)
from didcomm.core.types import (
    DIDCommFields,
    EncryptResult,
    DIDCommGeneratorType
)
from didcomm.core.defaults import DEF_ENC_ALG_ANON
from didcomm.core.converters import converter__didcomm_id
from didcomm.core.serialization import (
    json_str_to_dict,
    json_bytes_to_dict
)
from didcomm.core.anoncrypt import (
    find_keys_and_anoncrypt,
    unpack_anoncrypt
)
from didcomm.core.utils import get_did, is_did, is_did_url
from didcomm.did_doc.did_doc import DIDCommService


logger = logging.getLogger(__name__)


@dataclass
class ForwardBody:
    next: DID_OR_DID_URL


@attr.s(auto_attribs=True)
class ForwardMessage(GenericMessage[ForwardBody]):
    # if not specified would be auto-generated
    id: Optional[Union[str, Callable]] = attr.ib(
        converter=converter__didcomm_id,
        validator=attr.validators.instance_of(str),
        default=None
    )

    @staticmethod
    def _body_from_dict(body: dict) -> ForwardBody:
        return ForwardBody(**body)


@attr.s(auto_attribs=True)
class ForwardPackResult:
    msg: ForwardMessage
    msg_encrypted: EncryptResult


@dataclass
class ForwardResult:
    forward_msg: ForwardMessage
    forwarded_msg: JSON
    forwarded_msg_encrypted_to: Optional[List[DID_URL]] = None


async def find_did_service(
    resolvers_config: ResolversConfig,
    to: DID_OR_DID_URL,
    service_id: str = None
) -> DIDCommService:

    to_did = get_did(to)
    did_doc = await resolvers_config.did_resolver.resolve(to_did)

    if did_doc is None:
        raise DIDDocNotResolvedError()

    if service_id:
        did_service = did_doc.get_didcomm_service(service_id)
        if did_service is None:
            # TODO define exc attrs instead of explicit message
            raise InvalidDIDDocError(
                f"service with service id '{service_id}' not found"
                f" for for DID '{to}'"
            )
        return did_service
    else:
        try:
            # using the first as per spec
            # >Entries are SHOULD be specified in order of receiver preference
            # https://identity.foundation/didcomm-messaging/spec/#multiple-endpoints
            return did_doc.didcomm_services[0]
        except IndexError:
            return None


async def resolve_did_services_chain(
    resolvers_config: ResolversConfig,
    to: DID_OR_DID_URL,
    service_id: str = None,
    did_recursion=False
) -> List[DIDCommService]:

    res = []

    to_did_service = await find_did_service(
        resolvers_config, to, service_id
    )
    if to_did_service is None:
        return res

    service_uri = to_did_service.service_endpoint
    res.append(to_did_service)

    # alternative endpoints
    while is_did(service_uri) or is_did_url(service_uri):
        mediator_did = service_uri

        if len(res) > 1:
            # TODO cover possible case of alternative endpoints in mediator's
            #      DID Doc services (it SHOULD NOT be as per spec but ...)
            exc_t = (
                NotImplementedError if did_recursion else
                InvalidDIDDocError
            )
            raise exc_t(
                f"mediator '{res[-2].service_endpoint}' defines alternative"
                f" endpoint '{service_uri}' recursively"
            )

        # TODO check not only first item in mediator services list
        #      (e.g. first one may use alternative endpoint but second - URI)

        # resolve until final URI is reached
        mediator_did_service = await find_did_service(
           resolvers_config, mediator_did
        )
        if mediator_did_service is None:
            raise InvalidDIDDocError(
                f"mediator '{mediator_did}' service doc not found"
            )

        service_uri = mediator_did_service.service_endpoint
        res.append(mediator_did_service)

    return res


async def wrap_in_forward(
    resolvers_config: ResolversConfig,
    packed_msg: Union[JSON_OBJ, JSON],
    to: DID_OR_DID_URL,
    routing_keys: List[DID_OR_DID_URL],
    enc_alg_anon: Optional[AnonCryptAlg] = DEF_ENC_ALG_ANON,
    headers: Optional[List[Header]] = None,
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
    for _to, _next in zip(
        routing_keys[::-1], (routing_keys[1:] + [to])[::-1]
    ):
        fwd_attach = Attachment(
            data=AttachmentDataJson(packed_msg)
        )

        fwd_msg = ForwardMessage(
            id=didcomm_id_generator,
            body=ForwardBody(next=_next),
            type=DIDCommMessageProtocolTypes.FORWARD.value,
            attachments=[fwd_attach],
            **headers
        )

        fwd_msg_encrypted = await find_keys_and_anoncrypt(
            fwd_msg.as_dict(), _to, enc_alg_anon, resolvers_config
        )

        packed_msg = fwd_msg_encrypted.msg

    logger.debug(f"forward wrapping result: {fwd_msg_encrypted.msg}")

    return ForwardPackResult(
        fwd_msg,
        fwd_msg_encrypted
    )


async def unpack_forward(
    resolvers_config: ResolversConfig,
    packed_msg: JSON,
    decrypt_by_all_keys: bool
) -> ForwardResult:
    """
    Can be called by a Mediator who expects a Forward message to be unpacked

    :param resolvers_config: secrets and DIDDoc resolvers
    :param packed_msg: a Forward message as JSON string to be unpacked

    :raises DIDDocNotResolvedError: If a DID can not be resolved to a DID Doc.
    :raises DIDUrlNotFoundError: If a DID URL (for example a key ID) is not found within a DID Doc
    :raises SecretNotFoundError: If there is no secret for the given DID or DID URL (key ID)
    :raises MalformedMessageError: if the message is invalid (can not be decrypted, signature is invalid, the plaintext is invalid, etc.)

    :return: Forward plaintext
    """
    fwd_unpack_res = await unpack_anoncrypt(
        json_str_to_dict(packed_msg), resolvers_config, decrypt_by_all_keys)

    fwd_msg_dict = json_bytes_to_dict(fwd_unpack_res.msg)

    if not is_forward(fwd_msg_dict):
        raise MalformedMessageError(
            MalformedMessageCode.INVALID_PLAINTEXT
        )

    fwd_msg = ForwardMessage.from_dict(fwd_msg_dict)
    msg = fwd_msg.attachments[0].data.json

    logger.debug(
        f"unpacked Forward: forwarded msg {msg}, to_kids"
        f" {fwd_unpack_res.to_kids}"
    )

    return ForwardResult(
        forward_msg=fwd_msg,
        forwarded_msg=msg,
        forwarded_msg_encrypted_to=fwd_unpack_res.to_kids
    )


# TODO CONSIDER forward validation might be a part of ForwardMessage
def is_forward(msg: dict) -> bool:
    """
    A helper method to check if the given message is a Forward message.

    :param message: the message to be checked
    :return: True if the plaintext is a valid Forward message and false otherwise
    """
    # 'next' is required
    if DIDCommFields.NEXT not in msg.get(DIDCommFields.BODY, {}):
        return False
    # non-empty 'attachments' is required
    if not msg.get(DIDCommFields.ATTACHMENTS, []):
        return False
    # TODO other constraints ???
    #   - single item list of attachments
    #   - json AttachmentDataJson as data
    return True
