import pytest as pytest

from didcomm.common.resolvers import ResolversConfig
from didcomm.message import Message, FromPrior
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.secrets.secrets_resolver_in_memory import SecretsResolverInMemory
from didcomm.unpack import unpack
from didcomm.protocols.forward.forward import unpack_forward
from tests.test_vectors.common import CHARLIE_DID, BOB_DID, ALICE_DID
from tests.test_vectors.secrets.mock_secrets_resolver_alice import (
    MockSecretsResolverAlice,
)
from tests.test_vectors.secrets.mock_secrets_resolver_charlie import (
    MockSecretsResolverCharlie,
)


class MockSecretsResolverAliceNewDid(SecretsResolverInMemory):
    def __init__(self):
        super().__init__(
            secrets=list(MockSecretsResolverAlice()._secrets.values())
            + list(MockSecretsResolverCharlie()._secrets.values())
        )


@pytest.fixture()
def secrets_resolver_alice_with_new_did():
    return MockSecretsResolverAliceNewDid()


@pytest.fixture()
def resolvers_config_alice_with_new_did(
    secrets_resolver_alice_with_new_did, did_resolver
):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_alice_with_new_did, did_resolver=did_resolver
    )


@pytest.mark.asyncio
async def test_demo_attachments(
    resolvers_config_alice_with_new_did, resolvers_config_bob,
    resolvers_config_mediator1
):
    # ALICE
    frm_prior = FromPrior(iss=ALICE_DID, sub=CHARLIE_DID)
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=CHARLIE_DID,
        to=[BOB_DID],
        created_time=1516269022,
        expires_time=1516385931,
        from_prior=frm_prior,
    )
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice_with_new_did,
        message=message,
        frm=CHARLIE_DID,
        to=BOB_DID,
        pack_config=PackEncryptedConfig()
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(
        resolvers_config_mediator1, packed_msg, True
    )
    print(f"Got {forward_bob.forwarded_msg}")

    # BOB
    unpack_result = await unpack(
        resolvers_config_bob,
        forward_bob.forwarded_msg
    )
    print(f"Got ${unpack_result.message}")
