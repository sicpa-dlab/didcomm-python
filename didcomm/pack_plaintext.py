from __future__ import annotations

import json

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JSON
from didcomm.message import Message


async def pack_plaintext(resolvers_config: ResolversConfig, message: Message) -> JSON:
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


    :raises DIDNotResolvedError: If a DID or DID URL (key ID) can not be resolved or not found
    :raises SecretNotResolvedError: If there is no secret for the given DID or DID URL (key ID)

    :return: A packed message as a JSON string.
    """
    return json.dumps(message.as_dict())
