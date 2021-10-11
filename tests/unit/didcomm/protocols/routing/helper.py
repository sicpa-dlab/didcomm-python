from typing import Optional, Any, List, Dict

from didcomm.message import Attachment, AttachmentDataJson

from didcomm.protocols.routing.forward import ForwardBody, ForwardMessage


# TODO add more if needed
diff_type_objects = ["1", 2, [3], (4,), {5: 6}, lambda: "7", (8 == 9), {10}]


def gen_fwd_msg():
    return ForwardMessage(
        body=ForwardBody(next="did:example:123"),
        attachments=[Attachment(data=AttachmentDataJson({"some": "msg"}))],
    )


def gen_fwd_msg_dict(
    update: Optional[Dict[str, Any]] = None, remove: Optional[List[str]] = None
):
    remove = remove or []
    update = update or {}

    res = gen_fwd_msg().as_dict()
    res.update(update)

    for i in remove:
        del res[i]

    return res
