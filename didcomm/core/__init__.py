from authlib.jose import JsonWebEncryption
from authlib.jose.drafts import register_jwe_draft

register_jwe_draft(JsonWebEncryption)
