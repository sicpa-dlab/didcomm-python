import pytest as pytest

from didcomm.message import Attachment, Message, AttachmentDataJson
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.protocols.routing.forward import unpack_forward
from didcomm.unpack import unpack
from tests.test_vectors.common import ALICE_DID, BOB_DID


@pytest.mark.asyncio
async def test_demo_attachments(
    resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
):
    # ALICE
    attachment = Attachment(
        id="123",
        data=AttachmentDataJson(json={"foo": "bar"}),
        description="foo attachment",
        media_type="application/didcomm-encrypted+json",
    )
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=ALICE_DID,
        to=[BOB_DID],
        created_time=1516269022,
        expires_time=1516385931,
        attachments=[attachment],
    )
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=message,
        frm=ALICE_DID,
        to=BOB_DID,
        pack_config=PackEncryptedConfig(),
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(resolvers_config_mediator1, packed_msg, True)
    print(f"Got {forward_bob.forwarded_msg}")

    # BOB
    unpack_result = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)
    print(f"Got ${unpack_result.message}")
