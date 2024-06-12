from unittest.mock import patch


def test_import_fallback():
    with patch("importlib.resources.files", side_effect=ImportError):
        from bipsea.bip39 import files

        print(files)
