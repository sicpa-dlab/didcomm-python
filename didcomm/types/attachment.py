from typing import NamedTuple, Optional, List

from didcomm.types.types import JWS, JWE, JSON


class AttachmentData(NamedTuple):
    """data property of an attachment."""
    jws: Optional[JWS] = None
    jwe: Optional[JWE] = None
    json: Optional[JSON] = None
    base64: Optional[str] = None
    links: Optional[List[str]] = None
    hash: Optional[str] = None


class Attachment(NamedTuple):
    """attachments list element of a plaintext."""
    id: str
    data: AttachmentData
    description: Optional[str] = None
    filename: Optional[str] = None
    mime_type: Optional[str] = None
    format: Optional[str] = None
    lastmod_time: Optional[int] = None
    byte_count: Optional[int] = None
