from didcomm.common.algorithms import AnonCryptAlg, AuthCryptAlg


DEF_ENC_ALG_AUTH: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW
DEF_ENC_ALG_ANON: AuthCryptAlg = AnonCryptAlg.XC20P_ECDH_ES_A256KW
