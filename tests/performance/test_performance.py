from time import perf_counter_ns

import pytest
import pytest_asyncio

from didcomm import PackEncryptedConfig, pack_encrypted, unpack, UnpackConfig
from tests.test_vectors.common import BOB_DID, ALICE_DID
from tests.test_vectors.didcomm_messages.messages import TEST_MESSAGE

RECIPIENT_KEYS_COUNT = [1, 2, 3]
SAMPLES_COUNT = 1000


async def measure_naive(sampler, count):
    start = perf_counter_ns()
    for i in range(count):
        await sampler()
    end = perf_counter_ns()
    time_in_ns = end - start
    time_in_ms = time_in_ns / 1000000
    return time_in_ms


def dump_res(
    operations,
    time_in_ms,
    recipient_keys_count,
    unpack=False,
    authcrypt=False,
    signed=False,
):
    avrg = time_in_ms / operations
    thrpt = 1 / avrg

    op_type = "unpack" if unpack else "pack"
    enc_type = "_auth" if authcrypt else "_anon"
    signed_or_not = "_signed" if signed else ""

    op_descr = (
        f"'{op_type}{enc_type}_encrypted{signed_or_not}' [{recipient_keys_count} kIds]:"
    )

    print(
        f"\nbenchmark of {op_descr:40}"
        f" {time_in_ms:7.3f} ms, {operations:7} ops, {thrpt:10.3f} ops/ms, {avrg:7.3f} mss/op"
    )


@pytest.fixture()
def resolvers_config_alice(resolvers_config_alice_all_in_secrets):
    return resolvers_config_alice_all_in_secrets


@pytest.fixture()
def resolvers_config_bob(resolvers_config_bob_all_in_secrets):
    return resolvers_config_bob_all_in_secrets


@pytest_asyncio.fixture()
async def all_bob_key_agreement_kids(resolvers_config_alice):
    bob_did_doc = await resolvers_config_alice.did_resolver.resolve(BOB_DID)
    all_key_agreement_kids = bob_did_doc.key_agreement_kids
    yield all_key_agreement_kids
    bob_did_doc.key_agreement_kids = all_key_agreement_kids


@pytest.mark.skip(reason="disabled to skip on CI")
@pytest.mark.asyncio
@pytest.mark.parametrize("recipient_keys_count", RECIPIENT_KEYS_COUNT)
@pytest.mark.parametrize("sign_frm", [None, ALICE_DID])
@pytest.mark.parametrize("frm", [None, ALICE_DID])
async def test_pack_encrypted(
    frm,
    sign_frm,
    recipient_keys_count,
    resolvers_config_alice,
    all_bob_key_agreement_kids,
):
    bob_did_doc = await resolvers_config_alice.did_resolver.resolve(BOB_DID)
    bob_did_doc.key_agreement_kids = all_bob_key_agreement_kids[:recipient_keys_count]

    async def sample():
        pack_config = PackEncryptedConfig()

        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=TEST_MESSAGE,
            to=BOB_DID,
            frm=frm,
            sign_frm=sign_frm,
            pack_config=pack_config,
        )

    time_is_ms = await measure_naive(sample, SAMPLES_COUNT)
    dump_res(
        SAMPLES_COUNT,
        time_is_ms,
        recipient_keys_count,
        False,
        bool(frm),
        bool(sign_frm),
    )


@pytest.mark.skip(reason="disabled to skip on CI")
@pytest.mark.asyncio
@pytest.mark.parametrize("recipient_keys_count", RECIPIENT_KEYS_COUNT)
@pytest.mark.parametrize("sign_frm", [None, ALICE_DID])
@pytest.mark.parametrize("frm", [None, ALICE_DID])
async def test_unpack_encrypted(
    frm,
    sign_frm,
    recipient_keys_count,
    resolvers_config_alice,
    resolvers_config_bob,
    all_bob_key_agreement_kids,
):
    bob_did_doc = await resolvers_config_alice.did_resolver.resolve(BOB_DID)
    bob_did_doc.key_agreement_kids = all_bob_key_agreement_kids[:recipient_keys_count]

    pack_config = PackEncryptedConfig()

    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=TEST_MESSAGE,
        to=BOB_DID,
        frm=frm,
        sign_frm=sign_frm,
        pack_config=pack_config,
    )

    async def sample():
        unpack_config = UnpackConfig(expect_decrypt_by_all_keys=True)

        await unpack(
            resolvers_config=resolvers_config_bob,
            packed_msg=pack_result.packed_msg,
            unpack_config=unpack_config,
        )

    time_is_ms = await measure_naive(sample, SAMPLES_COUNT)
    dump_res(
        SAMPLES_COUNT, time_is_ms, recipient_keys_count, True, bool(frm), bool(sign_frm)
    )
