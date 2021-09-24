from time import perf_counter_ns

import pytest

from didcomm.pack_encrypted import PackEncryptedConfig, pack_encrypted
from didcomm.unpack import unpack, UnpackConfig
from tests.test_vectors.common import BOB_DID, ALICE_DID
from tests.test_vectors.didcomm_messages.messages import TEST_MESSAGE
from tests.unit.spec_test_vectors.conftest import resolvers_config_alice, resolvers_config_bob, did_resolver

RECIPIENT_KEYS_COUNT = [1, 2, 3]
SAMPLES_COUNT = 1000


async def measure_average(sampler, count):
    start = perf_counter_ns()
    for i in range(count):
        await sampler()
    end = perf_counter_ns()
    avg_time_per_sample = (end - start) / count
    return avg_time_per_sample


@pytest.fixture
async def all_bob_key_agreement_kids(resolvers_config_alice):
    bob_did_doc = await resolvers_config_alice.did_resolver.resolve(BOB_DID)
    all_key_agreement_kids = bob_did_doc.key_agreement_kids
    yield all_key_agreement_kids
    bob_did_doc.key_agreement_kids = all_key_agreement_kids


@pytest.mark.asyncio
@pytest.mark.parametrize("recipient_keys_count", RECIPIENT_KEYS_COUNT)
async def test_pack_anon_encrypted(
        recipient_keys_count, resolvers_config_alice, all_bob_key_agreement_kids):

    bob_did_doc = await resolvers_config_alice.did_resolver.resolve(BOB_DID)
    bob_did_doc.key_agreement_kids = all_bob_key_agreement_kids[:recipient_keys_count]

    async def sample():
        pack_config = PackEncryptedConfig()

        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=TEST_MESSAGE,
            to=BOB_DID,
            pack_config=pack_config,
        )

    avg_time = await measure_average(sample, SAMPLES_COUNT)

    print()
    print(f"pack_anon_encrypted for {recipient_keys_count} recipient keys takes {avg_time} ns in average")


@pytest.mark.asyncio
@pytest.mark.parametrize("recipient_keys_count", RECIPIENT_KEYS_COUNT)
async def test_unpack_anon_encrypted(
        recipient_keys_count, resolvers_config_alice, resolvers_config_bob, all_bob_key_agreement_kids):

    bob_did_doc = await resolvers_config_alice.did_resolver.resolve(BOB_DID)
    bob_did_doc.key_agreement_kids = all_bob_key_agreement_kids[:recipient_keys_count]

    pack_config = PackEncryptedConfig()

    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=TEST_MESSAGE,
        to=BOB_DID,
        pack_config=pack_config,
    )

    async def sample():
        unpack_config = UnpackConfig(expect_decrypt_by_all_keys=True)

        await unpack(
            resolvers_config=resolvers_config_bob, packed_msg=pack_result.packed_msg, unpack_config=unpack_config
        )

    avg_time = await measure_average(sample, SAMPLES_COUNT)

    print()
    print(f"unpack_anon_encrypted for {recipient_keys_count} recipient keys takes {avg_time} ns in average")


@pytest.mark.asyncio
@pytest.mark.parametrize("recipient_keys_count", RECIPIENT_KEYS_COUNT)
async def test_pack_auth_encrypted(
        recipient_keys_count, resolvers_config_alice, all_bob_key_agreement_kids):

    bob_did_doc = await resolvers_config_alice.did_resolver.resolve(BOB_DID)
    bob_did_doc.key_agreement_kids = all_bob_key_agreement_kids[:recipient_keys_count]

    async def sample():
        pack_config = PackEncryptedConfig()

        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=TEST_MESSAGE,
            frm=ALICE_DID,
            to=BOB_DID,
            pack_config=pack_config,
        )

    avg_time = await measure_average(sample, SAMPLES_COUNT)

    print()
    print(f"pack_auth_encrypted for {recipient_keys_count} recipient keys takes {avg_time} ns in average")


@pytest.mark.asyncio
@pytest.mark.parametrize("recipient_keys_count", RECIPIENT_KEYS_COUNT)
async def test_unpack_auth_encrypted(
        recipient_keys_count, resolvers_config_alice, resolvers_config_bob, all_bob_key_agreement_kids):

    bob_did_doc = await resolvers_config_alice.did_resolver.resolve(BOB_DID)
    bob_did_doc.key_agreement_kids = all_bob_key_agreement_kids[:recipient_keys_count]

    pack_config = PackEncryptedConfig()

    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=TEST_MESSAGE,
        frm=ALICE_DID,
        to=BOB_DID,
        pack_config=pack_config,
    )

    async def sample():
        unpack_config = UnpackConfig(expect_decrypt_by_all_keys=True)

        await unpack(
            resolvers_config=resolvers_config_bob, packed_msg=pack_result.packed_msg, unpack_config=unpack_config
        )

    avg_time = await measure_average(sample, SAMPLES_COUNT)

    print()
    print(f"unpack_auth_encrypted for {recipient_keys_count} recipient keys takes {avg_time} ns in average")
