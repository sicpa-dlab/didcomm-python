from didcomm.vendor.authlib.jose import JsonWebEncryption
from didcomm.vendor.authlib.jose.drafts import register_jwe_draft

register_jwe_draft(JsonWebEncryption)
