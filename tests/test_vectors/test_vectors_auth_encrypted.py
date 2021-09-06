from authlib.common.encoding import json_dumps

from didcomm.common.algorithms import AuthCryptAlg, SignAlg, AnonCryptAlg
from didcomm.unpack import Metadata
from tests.test_vectors.test_vectors_common import TestVector

TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_X25519 = json_dumps(
    {
        "ciphertext": "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
        "protected": "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ",
        "recipients": [
            {
                "encrypted_key": "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
                "header": {"kid": "did:example:bob#key-x25519-1"},
            },
            {
                "encrypted_key": "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
                "header": {"kid": "did:example:bob#key-x25519-2"},
            },
            {
                "encrypted_key": "aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
                "header": {"kid": "did:example:bob#key-x25519-3"},
            },
        ],
        "tag": "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
        "iv": "o02OXDQ6_-sKz2PX_6oyJg",
    }
)

TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_P256 = json_dumps(
    {
        "ciphertext": "WCufCs2lMZfkxQ0JCK92lPtLFgwWk_FtRWOMj52bQISa94nEbIYqHDUohIbvLMgbSjRcJVusZO04UthDuOpSSTcV5GBi3O0cMrjyI_PZnTb1yikLXpXma1bT10D2r5TPtzRMxXF3nFsr9y0JKV1TsMtn70Df2fERx2bAGxcflmd-A2sMlSTT8b7QqPtn17Yb-pA8gr4i0Bqb2WfDzwnbfewbukpRmPA2hsEs9oLKypbniAafSpoiQjfb19oDfsYaWWXqsdjTYMflqH__DqSmW52M-SUp6or0xU0ujbHmOkRkcdh9PsR5YsPuIWAqYa2hfjz_KIrGTxvCos0DMiZ4Lh_lPIYQqBufSdFH5AGChoekFbQ1vcyIyYMFugzOHOgZ2TwEzv94GCgokBHQR4_qaU_f4Mva64KPwqOYdm5f4KX16afTJa-IV7ar7__2L-A-LyxmC5KIHeGOedV9kzZBLC7TuzRAuE3vY7pkhLB1jPE6XpTeKXldljaeOSEVcbFUQtsHOSPz9JXuhqZ1fdAx8qV7hUnSAd_YMMDR3S6SXtem8ak2m98WPvKIxhCbcto7W2qoNYMT7MPvvid-QzUvTdKtyovCvLzhyYJzMjZxmn9-EnGhZ5ITPL_xFfLyKxhSSUVz3kSwK9xuOj3KpJnrrD7xrp5FKzEaJVIHWrUW90V_9QVLjriThZ36fA3ipvs8ZJ8QSTnGAmuIQ6Z2u_r4KsjL_mGAgn47qyqRm-OSLEUE4_2qB0Q9Z7EBKakCH8VPt09hTMDR62aYZYwtmpNs9ISu0VPvFjh8UmKbFcQsVrz90-x-r-Q1fTX9JaIFcDy7aqKcI-ai3tVF_HDR60Jaiw",
        "protected": "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJObHJ3UHZ0SUluZWNpeUVrYTRzMi00czhPalRidEZFQVhmTC12Z2x5enFvIiwieSI6ImhiMnZkWE5zSzVCQ2U3LVhaQ0dfLTY0R21UT19rNUlNWFBaQ00xdGFUQmcifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXktcDI1Ni0xIiwiYXB1IjoiWkdsa09tVjRZVzF3YkdVNllXeHBZMlVqYTJWNUxYQXlOVFl0TVEiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImFsZyI6IkVDREgtMVBVK0EyNTZLVyJ9",
        "recipients": [
            {
                "encrypted_key": "ZIL6Leligq1Xps_229nlo1xB_tGxOEVoEEMF-XTOltI0QXjyUoq_pFQBCAnVdcWNH5bmaiuzCYOmZ9lkyXBkfHO90KkGgODG",
                "header": {"kid": "did:example:bob#key-p256-1"},
            },
            {
                "encrypted_key": "sOjs0A0typIRSshhQoiJPoM4o7YpR5LA8SSieHZzmMyIDdD8ww-4JyyQhqFYuvfS4Yt37VF4z7Nd0OjYVNRL-iqPnoJ3iCOr",
                "header": {"kid": "did:example:bob#key-p256-2"},
            },
        ],
        "tag": "nIpa3EQ29hgCkA2cBPde2HpKXK4_bvmL2x7h39rtVEc",
        "iv": "mLqi1bZLz7VwqtVVFsDiLg",
    }
)

TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_P256_SIGNED = json_dumps(
    {
        "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures": [
            {
                "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                "signature": "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                "header": {"kid": "did:example:alice#key-1"},
            }
        ],
    }
)

TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_P521 = json_dumps(
    {
        "ciphertext": "lfYmR7CNas5hOePxWQEkUEwzSRds3t5GkMW4VUZKJWJ7H3y1X8a1RnUg3c0BCqdszzhZk8xE0vfQ67vJAWGdev8OWy7oGY_e1o4iAVj3mPNfnV5N7sjld6yUhrxqDsxtmVAp7LAipbJNhxqBoEXdb8hPbdPeUIov-5X0_cQHpHalSD6zMoyUPb0cCnw8bfmdN3aaVDrzsZRIkvhezZCkaQFMO75XKVEDyTzn8Eqwgpg_tzD_Hr00jHa9mTyTiDA_1ZzqleF-XSe5NEtFc7_BukgjPWMZAouPMWwIP0h-BPULxUzYcWKfC6hiU2ZuxWz8Fs8v9r6MCAaPOG37oA_yfWwE_FWl7x61sl6iZfDVQhOTkdlXNoZ0LiaC4ImXop2wSvKimkGqhysj1OefrUrpHmSx1qNz7vCWqW8Mo7fykXQCVYr6zXmcvWF5-KvXDu6DR3EFlgs6An9tWLv1flDrZWb-lS6RlL6Z8AqmLjP0Yb2r6mTopiulTTpXXpwe-Qs1_DHDGi0DfsZmcYhyra-F8YQ3tGIgy6wWCtyBh7Fq_zRy8RMvV3DkaLHYTekIle0YOoRdZRJBb3ycXHycIi7iT1ewOFlIGjsBg73Hkqa6O1weewS3uIxl4veO6cBOksfDRpC279X9tV1HDqROBolNBsWHQ2UpUD1Bat8UnfJMrwBcZkGQCjhlR9SSlZzEIqP3leRh5e2y2FGTm7wNRNwmgl6s6OUiKD-nbUnnSugGzolbavafHS80XrdfEuUyuPjnpQQQROapFfcjd7dSLd58g9OjOEqb1-Edk4KcW-yYU17_zfIzv1qykEH7F22Nq9HGbReXuao83ItUWgpBDZ-uf-_RbcpW2X1U5QGnI1SF4Trbhx74lnswEF_AlZ4SUh7frcMfKQLYobT1X_wIEY8pwN1AzWf482LJKKsxm0EcY73vf0n3uT_OS3EgBNCVYyF6_snm7MdOV-RM5ZZyQl64BsZ4aL4RVVCOa8bxYGPxvpOf9Ay-aQjwYQfyFxayRJiQWkywk8SRAdLLfSiveqvXAoIIi_XI98CRIaJ6DSKr-TuCDlz4yVP_8emS_S0S7F-Buh-P6nzjdJ04CAm95p6do_q8jk1IRHvubqrPKcpvk4U3p-6obJK9feJPffoe3-ddJvKJ5h8Et3xEKG7oId3NkbbFfYUnkEyC_wUeKtyrXK8uBz5HKhW1S27qsBAnKv5WTCyfrDsfX0eTaqdeJ3O9uR4niBc2sa2t89G5AEKWcOUnJcytAAAuhMZiz2zXXhmffPG5A7QSmZMAl75CP6ulN0KCBE0nTeuvNPueqpF4PV4CCcMfokz0hu5k5oo9FHfkQMVDBTiQUtEezIXiglqhu6VwcDgbbatAKUIYxnoisHKPg17zGMl5VMULVY5WBYPAUylKpWELnMc9BHUHNUxfSVlqdd847v__D1Go17MTsQujVGQQuM61Ay0-z1JwN0fki0M8t20U_sWX5jNMbdZCPBxy7rpZlztaF01j1NCaM3ZPh-_KLy8vQ584R5I5LlE5OejgyLQYMOMzSgUZZEAeTGV_S-kEnt36k-L8Kbyv_LWuiuTQzwLSwlmWOKLdDbmjEjA1JsEaKmorDKz0q7MFIoC-gKKJBjPTJ5PxJLJj4RHOxxDWhx00HjLLE3S1B6uAvKVUhN4ka_wWusVqffrRZm_e7Oz0hbCO8pT4tzlbFWTu0-O44kHkRjfubEi4PnaNzKbGMXTrDo7aY6sgiDB8KlJSsKrNeG0OLjBAYF_zmHlrqctFQidTD_YIDzcSfkCTrMoOYa07nXG6E1nArScOgkNuNkPVhCq_VD6w-pZ1mSUBwKVCnjNueTrB5RvFBydaoWcAAX3OtH8yFeDWGzlRYWJNKEKull_Vah8B7nwwnTPxyeUwnr2txlwDvLx9ASrl5CjwvLc9bL7jCa6SrWt3hPjvjDY4JdFxnCqyyXD11Mpt2kyA4TTBaBbzI5Kja6pKsCUw0QCTCfTBu7bKGTOJKai32c4WRXvpVgIowOzdyjtKD0LgnY2fRTpJWpcTMVAHPfSad0jc23iTwOKcJQ0n_ExfOxzW_PSvAYbakrRwdZdDefb_fLrILxgS7OA9KepGQOJnp0-X_o1bBkXsm_cvVhcprLViUxHR1uCTMXaUl24viekps45aODvfBj5OsG3GrEShqtLb7ukEHEJjLsIe1l-4kFtNp4RlPZlapYgNyMSjnGopw2D51khuOHdJ2yLWASgFJPIa4dan4KTcDhp7qmbijN8JR_s_p1DB4E1nFlQPuncA8lIiuGv2PKHKXQkkuHcKmPMYTjRlam5IBHXQPV_njHMAIV60XU8kxa5G7t-Iwl_6OeRIj_HXdf5mfdTNEYlwbQWHInkS4U32RD9Kf0u6SC1bpRZx6AbFK8xlIgUPhB_sP3kG_ZZIZhcJ1Oy6Q7pAzmKXZYWKMkDWZk7a-WsiA0Z8gOcd7PYA13GRIw0MT_GIRcFRfkp7821j2ArHHo6jagqMdEuCZHzHrfwD0XHzT4FP3-aTaHIqrKx0TiYRfn2k2Q",
        "protected": "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTUyMSIsIngiOiJBYmxoeVVENUxYNE9zWDhGRTVaODRBX09CYThiOHdhVUhXSFExbTBnczhuSFVERDdySDlJRWRZbzJUSzFQYU5ha05aSk54a1FBWC1aUkxWa1BoNnV4eTJNIiwieSI6IkFQTjh6c0xEZGJpVjN0LTloWTJFQzFVZWEzTm5tMzFtNWowRmNiUWM0Y2ZWQmFNdzVCQ2VpcU9QWkljZTVMNjI4bnVORkxKR2szSjh6SVBPYUlLU0xmaTEifSwiYXB2IjoiR09lbzc2eW02TkNnOVdXTUVZZlcwZVZEVDU2Njh6RWhsMnVBSVctRS1IRSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
        "recipients": [
            {
                "encrypted_key": "iuVx5qAiRtijMfHnkF95_ByjHyiAmRqNTrExrEQK4p7HwW7sit1F0g",
                "header": {"kid": "did:example:bob#key-p521-1"},
            },
            {
                "encrypted_key": "6OWnv-tY1ZDUBt8uRNpmteoXTVDzRGz2UF04Y2eh2-bp2jiViU8VCw",
                "header": {"kid": "did:example:bob#key-p521-2"},
            },
        ],
        "tag": "pEh6LS1GCTYQaWR-6vAe_Q",
        "iv": "ZMHYqq1xV1X81bFzzEH_iAfBcL75fznZ",
    }
)

TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_P521_SIGNED = json_dumps(
    {
        "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures": [
            {
                "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                "signature": "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                "header": {"kid": "did:example:alice#key-1"},
            }
        ],
    }
)

TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH = [
    TestVector(
        TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_X25519,
        Metadata(
            encrypted=True,
            anonymous_sender=False,
            authenticated=True,
            non_repudiation=False,
            encrypted_from="did:example:alice#key-x25519-1",
            encrypted_to=[
                "did:example:bob#key-x25519-1",
                "did:example:bob#key-x25519-2",
                "did:example:bob#key-x25519-3",
            ],
            enc_alg_auth=AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW,
        ),
    ),
    TestVector(
        TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_P256,
        Metadata(
            encrypted=True,
            anonymous_sender=False,
            authenticated=True,
            non_repudiation=True,
            encrypted_from="did:example:alice#key-p256-1",
            sign_from="did:example:alice#key-1",
            encrypted_to=["did:example:bob#key-p256-1", "did:example:bob#key-p256-2"],
            enc_alg_auth=AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW,
            sign_alg=SignAlg.ED25519,
            signed_message=TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_P256_SIGNED,
        ),
    ),
    TestVector(
        TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_P521,
        Metadata(
            encrypted=True,
            anonymous_sender=True,
            authenticated=True,
            non_repudiation=True,
            encrypted_from="did:example:alice#key-p521-1",
            sign_from="did:example:alice#key-1",
            encrypted_to=["did:example:bob#key-p521-1", "did:example:bob#key-p521-2"],
            enc_alg_auth=AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW,
            enc_alg_anon=AnonCryptAlg.XC20P_ECDH_ES_A256KW,
            sign_alg=SignAlg.ED25519,
            signed_message=TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH_P521_SIGNED,
        ),
    ),
]
