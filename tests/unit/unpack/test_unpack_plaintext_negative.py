import pytest

from didcomm.unpack import unpack
from tests.test_vectors.common import TestVectorNegative
from tests.test_vectors.didcomm_messages.tests.test_vectors_plaintext_negative import (
    INVALID_PLAINTEXT_TEST_VECTORS,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("test_vector", INVALID_PLAINTEXT_TEST_VECTORS)
async def test_unpack_invalid_message(
    test_vector: TestVectorNegative, resolvers_config_bob
):
    with pytest.raises(test_vector.exc):
        await unpack(resolvers_config_bob, test_vector.value)
