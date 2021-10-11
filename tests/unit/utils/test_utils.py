from didcomm.core.utils import is_did


def test_is_did():
    assert is_did("did:example:alice")
    assert is_did("did:example:alice:alice2")
    assert is_did("did:example:alice#key-1")
    assert is_did("did:example:alice:alice2#key-1")

    assert not is_did("did:example")
    assert not is_did("did")
    assert not is_did("did:example#key-1")
