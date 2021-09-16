try:
    import mock

    mock_module = mock
except ImportError:
    import unittest.mock

    mock_module = unittest.mock
