from didcomm.did_doc.did_resolver_in_memory import DIDResolverInMemory
from tests.test_vectors.did_doc import (
    DID_DOC_ALICE_WITH_NO_SECRETS,
    DID_DOC_ALICE_SPEC_TEST_VECTORS,
    DID_DOC_BOB_WITH_NO_SECRETS,
    DID_DOC_BOB_SPEC_TEST_VECTORS,
    DID_DOC_CHARLIE,
    DID_DOC_MEDIATOR1,
    DID_DOC_MEDIATOR2
)


class MockDIDResolverAllInSecrets(DIDResolverInMemory):
    def __init__(self):
        super().__init__(
            did_docs=[
                DID_DOC_ALICE_SPEC_TEST_VECTORS,
                DID_DOC_BOB_SPEC_TEST_VECTORS,
                DID_DOC_CHARLIE,
                DID_DOC_MEDIATOR1,
                DID_DOC_MEDIATOR2
            ]
        )


class MockDIDResolverWithNonSecrets(DIDResolverInMemory):
    def __init__(self):
        super().__init__(
            did_docs=[
                DID_DOC_ALICE_WITH_NO_SECRETS,
                DID_DOC_BOB_WITH_NO_SECRETS,
                DID_DOC_CHARLIE,
            ]
        )
