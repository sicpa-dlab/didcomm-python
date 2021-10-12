from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JSON, DID_OR_DID_URL, DID_URL
from didcomm.core.serialization import dict_to_json
from didcomm.core.sign import sign
from didcomm.core.utils import is_did
from didcomm.errors import DIDCommValueError
from didcomm.core.from_prior import pack_from_prior_in_place
from didcomm.message import Message


async def pack_signed(
    resolvers_config: ResolversConfig,
    message: Message,
    sign_frm: DID_OR_DID_URL,
    pack_params: Optional[PackSignedParameters] = None,
) -> PackSignedResult:
    """
    Produces `DIDComm Signed Message`
    https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-message.

    The method signs (non-repudiation added) the message keeping it unencrypted.

    Signed messages are only necessary when
        - the origin of plaintext must be provable to third parties
        - or the sender can’t be proven to the recipient by authenticated encryption because the recipient
          is not known in advance (e.g., in a broadcast scenario).

    Adding a signature when one is not needed can degrade rather than enhance security because it
    relinquishes the sender’s ability to speak off the record.

    Signing is done as follows:
        - Signing is done via the keys from the `authentication` verification relationship in the DID Doc
          for the DID to be used for signing
        - If `sign_frm` is a DID, then the first sender's `authentication` verification method is used for which
          a private key in the _secrets resolver is found
        - If `sign_frm` is a key ID, then the sender's `authentication` verification method identified by the given key ID is used.

    :param resolvers_config: secrets and DIDDoc resolvers
    :param message: The message to be packed into a DIDComm message
    :param sign_frm: DID or key ID the sender uses for signing.
    :param pack_params: Optional parameters for pack

    :raises DIDDocNotResolvedError: If a DID can not be resolved to a DID Doc.
    :raises DIDUrlNotFoundError: If a DID URL (for example a key ID) is not found within a DID Doc
    :raises SecretNotFoundError: If there is no secret for the given DID or DID URL (key ID)
    :raises DIDCommValueError: If invalid input is provided.

    :return: PackSignedResult
    """
    pack_params = pack_params or PackSignedParameters()

    __validate(sign_frm)
    message = message.as_dict()

    from_prior_issuer_kid = await pack_from_prior_in_place(
        message,
        resolvers_config,
        pack_params.from_prior_issuer_kid,
    )

    sign_result = await sign(message, sign_frm, resolvers_config)
    packed_msg = dict_to_json(sign_result.msg)

    return PackSignedResult(
        packed_msg=packed_msg,
        sign_from_kid=sign_result.sign_frm_kid,
        from_prior_issuer_kid=from_prior_issuer_kid,
    )


@dataclass(frozen=True)
class PackSignedResult:
    """
    Result of pack operation.

    Attributes:
        packed_msg (str): A packed message as a JSON string
        sign_from_kid (DID_URL): Identifier (DID URL) of sender key used for message signing
        from_prior_issuer_kid (DID_URL): Identifier (DID URL) of issuer key used for signing from_prior.
                                         None if the message does not contain from_prior.
    """

    packed_msg: JSON
    sign_from_kid: DID_URL
    from_prior_issuer_kid: Optional[DID_URL] = None


@dataclass
class PackSignedParameters:
    """
    Optional parameters for pack.

    Attributes:
        from_prior_issuer_kid (DID_URL): If from_prior is specified in the source message,
            this field can explicitly specify which key to use for signing from_prior
            in the packed message
    """

    from_prior_issuer_kid: Optional[DID_URL] = None


def __validate(sign_frm: DID_OR_DID_URL):
    if not is_did(sign_frm):
        raise DIDCommValueError(
            f"`sign_from` value is not a valid DID of DID URL: {sign_frm}"
        )
