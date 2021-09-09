from didcomm.did_doc.did_resolver_in_memory import DIDResolverInMemory
from tests.test_vectors.did_doc.did_doc_alice import (
    DID_DOC_ALICE,
    DID_DOC_ALICE_SPEC_TEST_VECTORS,
)
from tests.test_vectors.did_doc.did_doc_bob import (
    DID_DOC_BOB,
    DID_DOC_BOB_SPEC_TEST_VECTORS,
)
from tests.test_vectors.did_doc.did_doc_charlie import DID_DOC_CHARLIE


class MockDIDResolver(DIDResolverInMemory):
    def __init__(self):
        super().__init__(did_docs=[DID_DOC_ALICE, DID_DOC_BOB, DID_DOC_CHARLIE])


class MockDIDResolverSpecTestVectors(DIDResolverInMemory):
    def __init__(self):
        super().__init__(
            did_docs=[
                DID_DOC_ALICE_SPEC_TEST_VECTORS,
                DID_DOC_BOB_SPEC_TEST_VECTORS,
                DID_DOC_CHARLIE,
            ]
        )
