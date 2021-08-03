from __future__ import annotations

from dataclasses import dataclass
from typing import List, Union

from didcomm.common.types import DID_OR_KID, JSON_DATA, JWK, JSON
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.plaintext import Plaintext, PlaintextHeaders
from didcomm.secrets.secrets_resolver import SecretsResolver
from didcomm.unpack import UnpackOpts


@dataclass(frozen=True)
class ForwardBody:
    next: DID_OR_KID
    forwarded_msg: JSON


@dataclass(frozen=True)
class ForwardPlaintext(PlaintextHeaders, ForwardBody):
    type: str = "https://didcomm.org/routing/2.0/forward"

    def to_json(self) -> JSON:
        return ""


class Forwarder:
    """
    Implementation of DID Comm Forward protocol.
    """

    def __init__(self, secrets_resolver: SecretsResolver = None, did_resolver: DIDResolver = None):
        """
        A new instance of Forwarder.

        :param secrets_resolver: an optional secrets resolver that can override a default secrets resolver
        registered by 'register_default_secrets_resolver'
        :param did_resolver: an optional DID Doc resolver that can override a default DID Doc resolver
        registered by 'register_default_did_resolver'
        """
        pass

    async def wrap_in_forward(self, packed_msg: Union[JSON_DATA, JSON], routing_keys: List[JWK]) -> JSON:
        """
        Wraps the given packed message in Forward messages for evert routing key.

        :param packed_msg: the message to be wrapped in Forward messages
        :param routing_keys: a list of routing keys in JWK format
        :return: a top-level Forward message as JSON string
        """
        return ""

    async def unpack_forward(self, msg: JSON) -> ForwardPlaintext:
        """
        Can be called by a Mediator who expects a Forward message to be unpacked

        :raises NotForwardTypeException: if unpacked plaintext is not a Forward message
        :raises UnknownRecipientException: if the target DID or keyID can not be resolved
        :raises IncompatibleKeysException: if the sender and target keys are not compatible
        :raises CanNotDecryptException: if the message can not be decrypted by the given recipient
        :raises InvalidForwardPackException: if the message is not packed for Forwarding properly

        :param msg: a Forward message as JSON string to be unpacked
        :return: Forward plaintext
        """
        return ForwardPlaintext(
            next="",
            forwarded_msg="",
            id="", type="")

    @staticmethod
    def parse_forward(plaintext: Plaintext) -> ForwardPlaintext:
        """
        Convert the given plaintext into a Forward message.

        :raises NotForwardTypeException: if unpacked plaintext is not a Forward message

        :param plaintext: the plaintext message to be converted
        :return: a Forward message instance
        """
        return ForwardPlaintext(
            next="",
            forwarded_msg="",
            id="", type="")

    @staticmethod
    def is_forward(plaintext: Plaintext) -> bool:
        """
        A helper method to check if the given plaintext is a Forward message.

        :param plaintext: the plaintext to be checked
        :return: True if the plaintext is a valid Forward message and false otherwise
        """
        return True

    @staticmethod
    def build_forward_unpack_opts() -> UnpackOpts:
        """
        Build Unpack options for unpacking a Forward message.

        :return: unpack options
        """
        return UnpackOpts(
            expect_signed=False,
            expect_encrypted=True,
            expect_authenticated=False,
            expect_decrypt_by_all_keys=False,
            unwrap_re_wrapping_forward=True
        )
