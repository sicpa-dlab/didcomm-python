import pytest as pytest

from didcomm.common.resolvers import ResolversConfig
from didcomm.message import Message, FromPrior
from didcomm.pack_encrypted import pack_encrypted
from didcomm.secrets.secrets_resolver_in_memory import SecretsResolverInMemory
from didcomm.unpack import unpack
from tests.test_vectors.mock_secrets_resolver_alice import MockSecretsResolverAlice
from tests.test_vectors.mock_secrets_resolver_charlie import MockSecretsResolverCharlie
from tests.test_vectors.test_vectors_common import ALICE_DID, CHARLIE_DID, BOB_DID


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
    resolvers_config_alice_with_new_did, resolvers_config_bob
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
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB
    unpack_result = await unpack(resolvers_config_bob, packed_msg)
    print(f"Got ${unpack_result.message}")
