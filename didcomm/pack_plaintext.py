from __future__ import annotations

from typing import Optional

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JSON
from didcomm.plaintext import Plaintext


async def pack_plaintext(plaintext: Plaintext, resolvers_config: Optional[ResolversConfig] = None) -> JSON:
    """
    Produces `DIDComm Plaintext Messages`
    https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages.

    A DIDComm message in its plaintext form, not packaged into any protective envelope,
    is known as a DIDComm plaintext message. Plaintext messages lack confidentiality and integrity
    guarantees, and are repudiable. They are therefore not normally transported across security boundaries.
    However, this may be a helpful format to inspect in debuggers, since it exposes underlying semantics,
    and it is the format used in this spec to give examples of headers and other internals.
    Depending on ambient security, plaintext may or may not be an appropriate format for DIDComm data at rest.

    :param plaintext: The plaintext to be packed
    :param resolvers_config: Optional resolvers that can override a default resolvers registered by
                             `register_default_secrets_resolver` and `register_default_did_resolver`

    :raises DIDNotResolvedError: If a DID or DID URL (key ID) can not be resolved or not found
    :raises SecretNotResolvedError: If there is no secret for the given DID or DID URL (key ID)

    :return: A packed message as a JSON string.
    """
    return ""
