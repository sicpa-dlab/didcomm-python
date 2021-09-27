import pytest

from didcomm.errors import MalformedMessageError
from didcomm.unpack import unpack
from tests.test_vectors.common import TTestVectorNegative
from tests.test_vectors.didcomm_messages.tests.test_vectors_anoncrypt_negative import (
    INVALID_ANONCRYPT_TEST_VECTORS,
    ANONCRYPT_MESSAGE_P256_XC20P_EPK_WRONG_POINT,
)
from tests.test_vectors.didcomm_messages.tests.test_vectors_authcrypt_negative import (
    INVALID_AUTHCRYPT_TEST_VECTORS,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("test_vector", INVALID_AUTHCRYPT_TEST_VECTORS)
async def test_unpack_authcrypt_message(
    test_vector: TTestVectorNegative, resolvers_config_bob
):
    with pytest.raises(test_vector.exc):
        await unpack(resolvers_config_bob, test_vector.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("test_vector", INVALID_ANONCRYPT_TEST_VECTORS)
async def test_unpack_anoncrypt_message(
    test_vector: TTestVectorNegative, resolvers_config_bob
):
    with pytest.raises(test_vector.exc):
        await unpack(resolvers_config_bob, test_vector.value)


@pytest.mark.asyncio
async def test_unpack_anoncrypt_message_epk_wrong_point(resolvers_config_bob):
    with pytest.raises(MalformedMessageError):
        await unpack(resolvers_config_bob, ANONCRYPT_MESSAGE_P256_XC20P_EPK_WRONG_POINT)
