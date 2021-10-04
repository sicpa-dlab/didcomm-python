import pytest

from didcomm.pack_plaintext import pack_plaintext
from tests.test_vectors.didcomm_messages.messages import (
    INVALID_FROM_PRIOR_TEST_VECTORS,
)


@pytest.mark.parametrize("test_vector", INVALID_FROM_PRIOR_TEST_VECTORS)
@pytest.mark.asyncio
async def test_pack_plaintext_with_invalid_from_prior(
    test_vector,
    resolvers_config_charlie_rotated_to_alice,
    resolvers_config_bob,
):
    with pytest.raises(test_vector.exc):
        await pack_plaintext(
            resolvers_config=resolvers_config_charlie_rotated_to_alice,
            message=test_vector.value,
        )
