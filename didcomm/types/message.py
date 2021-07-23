from __future__ import annotations

from typing import NamedTuple, Optional, List

from didcomm.types.types import Payload, DID


class Message(NamedTuple):
    payload: Payload
    id: str
    type: str
    typ: Optional[str] = None
    frm: Optional[DID] = None
    to: Optional[List[DID]] = None
    created_time: Optional[int] = None
    expires_time: Optional[int] = None

    @staticmethod
    def build(payload: Payload, id: str, type: str) -> MessageBuilder:
        return MessageBuilder(payload=payload, id=id, type=type)


class MessageBuilder:

    def __init__(self, payload: Payload, id: str, type: str) -> None:
        self.__payload = payload
        self.__id = id
        self.__type = type

    def finalize(self) -> Message:
        return Message(
            payload=self.__payload,
            id=self.__id,
            type=self.__type
        )

    def typ(self, typ: str) -> MessageBuilder:
        return self

    def frm(self, frm: DID) -> MessageBuilder:
        return self

    def to(self, to: List[DID]) -> MessageBuilder:
        return self

    def created_time(self, created_time: int) -> MessageBuilder:
        return self

    def expires_time(self, expires_time: int) -> MessageBuilder:
        return self
