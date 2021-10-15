# DIDComm Python

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Unit Tests](https://github.com/sicpa-dlab/didcomm-python/workflows/verify/badge.svg)](https://github.com/sicpa-dlab/didcomm-python/actions/workflows/verify.yml)
[![Python Package](https://img.shields.io/pypi/v/didcomm)](https://pypi.org/project/didcomm/)

Basic [DIDComm v2](https://identity.foundation/didcomm-messaging/spec) support in Python.

## Installation
```
pip install didcomm
```

## DIDComm + peerdid Demo
See https://github.com/sicpa-dlab/didcomm-demo.

## Assumptions and Limitations
- Python >= 3.7.
- In order to use the library, `SecretsResolver` and `DIDResolver` interfaces must be implemented on the application level. 
  Implementation of that interfaces is out of DIDComm library scope.  
  - Verification materials are expected in JWK, Base58 and Multibase (internally Base58 only) formats.
    - In Base58 and Multibase formats, keys using only X25519 and Ed25519 curves are supported.
    - For private keys in Base58 and Multibase formats, the verification material value contains both private and public parts (concatenated bytes).
    - In Multibase format, bytes of the verification material value is prefixed with the corresponding Multicodec code.
  - Key IDs (kids) used in `SecretsResolver` must match the corresponding key IDs from DID Doc verification methods.
  - Key IDs (kids) in DID Doc verification methods and secrets must be a full [DID Fragment](https://www.w3.org/TR/did-core/#fragment), that is `did#key-id`.
  - Verification methods referencing another DID Document are not supported (see [Referring to Verification Methods](https://www.w3.org/TR/did-core/#referring-to-verification-methods)).
- The following curves and algorithms are supported:
  - Encryption:
     - Curves: X25519, P-384, P-256, P-521
     - Content encryption algorithms: 
       - XC20P (to be used with ECDH-ES only, default for anoncrypt),
       - A256GCM (to be used with ECDH-ES only),
       - A256CBC-HS512 (default for authcrypt)
     - Key wrapping algorithms: ECDH-ES+A256KW, ECDH-1PU+A256KW
  - Signing:
    - Curves: Ed25519, Secp256k1, P-256
    - Algorithms: EdDSA (with crv=Ed25519), ES256, ES256K
- Forward protocol is implemented and used by default.
- DID rotation (`fromPrior` field) is supported.
- DIDComm has been implemented under the following [Assumptions](https://hackmd.io/i3gLqgHQR2ihVFV5euyhqg)   


## Examples

See [demo scripts](tests/demo) for details.

A general usage of the API is the following:
- Sender Side:
  - Build a `Message` (plaintext, payload).
  - Convert a message to a DIDComm Message for further transporting by calling one of the following:
     - `pack_encrypted` to build an Encrypted DIDComm message
     - `pack_signed` to build a Signed DIDComm message
     - `pack_plaintext` to build a Plaintext DIDComm message
- Receiver side:
  - Call `unpack` on receiver side that will decrypt the message, verify signature if needed
  and return a `Message` for further processing on the application level.

### 1. Build an Encrypted DIDComm message for the given recipient

This is the most common DIDComm message to be used in most of the applications.

A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) that 
- hides its content from all but authorized recipients
- (optionally) discloses and proves the sender to only those recipients
- provides message integrity guarantees

It is important in privacy-preserving routing. It is what normally moves over network transports in DIDComm
applications, and is the safest format for storing DIDComm data at rest.

See `pack_encrypted` documentation for more details.

**Authentication encryption** example (most common case):

```
# ALICE
message = Message(body={"aaa": 1, "bbb": 2},
                  id="1234567890", type="my-protocol/1.0",
                  frm=ALICE_DID, to=[BOB_DID])
pack_result = await pack_encrypted(message=message, frm=ALICE_DID, to=BOB_DID)
packed_msg = pack_result.packed_msg
print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

# BOB
unpack_result = await unpack(packed_msg)
print(f"Got ${unpack_result.message} message")
```

**Anonymous encryption** example:

```
message = Message(body={"aaa": 1, "bbb": 2},
                  id="1234567890", type="my-protocol/1.0",
                  frm=ALICE_DID, to=[BOB_DID])
pack_result = await pack_encrypted(message=message, to=BOB_DID)
```

**Encryption with non-repudiation** example:

```
message = Message(body={"aaa": 1, "bbb": 2},
                  id="1234567890", type="my-protocol/1.0",
                  frm=ALICE_DID, to=[BOB_DID])
pack_result = await pack_encrypted(message=message, frm=ALICE_DID, to=BOB_DID, sign_frm=ALICE_DID)
```

### 2. Build an unencrypted but Signed DIDComm message

Signed messages are only necessary when
- the origin of plaintext must be provable to third parties
- or the sender can’t be proven to the recipient by authenticated encryption because the recipient is not known in advance (e.g., in a
broadcast scenario).
 
Adding a signature when one is not needed can degrade rather than enhance security because it
relinquishes the sender’s ability to speak off the record.

See `pack_signed` documentation for more details.

```
# ALICE
message = Message(body={"aaa": 1, "bbb": 2},
                  id="1234567890", type="my-protocol/1.0",
                  frm=ALICE_DID, to=[BOB_DID])
packed_msg = await pack_signed(message=message, sign_frm=ALICE_DID)
packed_msg = pack_result.packed_msg
print(f"Publishing ${packed_msg}")

# BOB
unpack_result = await unpack(packed_msg)
print(f"Got ${unpack_result.message} message signed as ${unpack_result.metadata.signed_message}")
```

### 3. Build a Plaintext DIDComm message

A DIDComm message in its plaintext form that 
- is not packaged into any protective envelope
- lacks confidentiality and integrity guarantees
- repudiable

They are therefore not normally transported across security boundaries. 

```
# ALICE
message = Message(body={"aaa": 1, "bbb": 2},
                  id="1234567890", type="my-protocol/1.0",
                  frm=ALICE_DID, to=[BOB_DID])
packed_msg = await pack_plaintext(message)
print(f"Publishing ${packed_msg}")

# BOB
unpack_result = await unpack(packed_msg)
print(f"Got ${unpack_result.plaintext} message")
```

## Contribution
PRs are welcome!

The following CI checks are run against every PR:
- all tests must pass
- [flake8](https://github.com/PyCQA/flake8) checks must pass
- code must be formatted by [Black](https://github.com/psf/black)