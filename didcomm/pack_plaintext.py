from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JSON, DID_URL
from didcomm.core.serialization import dict_to_json
from didcomm.core.from_prior import pack_from_prior_in_place
from didcomm.message import Message


async def pack_plaintext(
    resolvers_config: ResolversConfig,
    message: Message,
    pack_params: Optional[PackPlaintextParameters] = None,
) -> PackPlaintextResult:
    """
    Produces `DIDComm Plaintext Messages`
    https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages.

    A DIDComm message in its plaintext form that
      - is not packaged into any protective envelope
      - lacks confidentiality and integrity guarantees
      - repudiable

    They are therefore not normally transported across security boundaries.

    However, this may be a helpful format to inspect in debuggers, since it exposes underlying semantics,
    and it is the format used in the DIDComm spec to give examples of headers and other internals.
    Depending on ambient security, plaintext may or may not be an appropriate format for DIDComm data at rest.

    :param resolvers_config: secrets and DIDDoc resolvers
    :param message: The message to be packed into a DIDComm message
    :param pack_params: Optional parameters for pack

    :raises DIDNotResolvedError: If a DID or DID URL (key ID) can not be resolved or not found
    :raises SecretNotResolvedError: If there is no secret for the given DID or DID URL (key ID)

    :return: PackPlaintextResult
    """
    pack_params = pack_params or PackPlaintextParameters()

    message = message.as_dict()

    from_prior_issuer_kid = await pack_from_prior_in_place(
        message,
        resolvers_config,
        pack_params.from_prior_issuer_kid,
    )

    packed_msg = dict_to_json(message)

    return PackPlaintextResult(packed_msg, from_prior_issuer_kid)


@dataclass(frozen=True)
class PackPlaintextResult:
    """
    Result of pack operation.

    Attributes:
        packed_msg (str): A packed message as a JSON string
        from_prior_issuer_kid (DID_URL): Identifier (DID URL) of issuer key used for signing from_prior.
                                         None if the message does not contain from_prior.
    """

    packed_msg: JSON
    from_prior_issuer_kid: Optional[DID_URL] = None


@dataclass
class PackPlaintextParameters:
    """
    Optional parameters for pack.

    Attributes:
        from_prior_issuer_kid (DID_URL): If from_prior is specified in the source message,
            this field can explicitly specify which key to use for signing from_prior
            in the packed message
    """

    from_prior_issuer_kid: Optional[DID_URL] = None
