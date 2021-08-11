from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JSON, DID_OR_DID_URL
from didcomm.plaintext import Plaintext


@dataclass(frozen=True)
class PackSignedResult:
    """
    Result of pack operation.

    Attributes:
        packed_msg (str): A packed message as a JSON string
        sign_from_kid (DID_OR_DID_URL): Identifier (DID URL) of sender key used for message signing
    """
    packed_msg: JSON
    sign_from_kid: DID_OR_DID_URL


async def pack_signed(plaintext: Plaintext,
                      sign_frm: DID_OR_DID_URL,
                      resolvers_config: Optional[ResolversConfig] = None) -> PackSignedResult:
    """
    Produces `DIDComm Signed Message`
    https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-message.

    The method signs (non-repudiation added) the message keeping it unencrypted.

    Signed messages are only necessary when the origin of plaintext must be provable
    to third parties, or when the sender can’t be proven to the recipient by authenticated encryption because
    the recipient is not known in advance (e.g., in a broadcast scenario).
    Adding a signature when one is not needed can degrade rather than enhance security because
    it relinquishes the sender’s ability to speak off the record.

    Signing is done as following:
        - Signing is done via the keys from the `authentication` verification relationship in the DID Doc
          for the DID to be used for signing
        - If `sign_frm` is a DID, then the first sender's `authentication` verification method is used for which
          a private key in the secrets resolver is found
        - If `sign_frm` is a key ID, then the sender's `authentication` verification method identified by the given key ID is used.

    :param plaintext: The plaintext to be packed
    :param sign_frm: DID or key ID the sender uses for signing.
    :param resolvers_config: Optional resolvers that can override a default resolvers registered by
                             `register_default_secrets_resolver` and `register_default_did_resolver`

    :raises DIDNotResolvedError: If a DID or DID URL (key ID) can not be resolved or not found
    :raises SecretNotResolvedError: If there is no secret for the given DID or DID URL (key ID)

    :return: A packed message as a JSON string.
    """
    return PackSignedResult("", "")
