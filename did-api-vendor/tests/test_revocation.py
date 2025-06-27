import importlib.util
from pathlib import Path
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location(
    "vc_utils", Path(__file__).resolve().parents[1] / "backend" / "vc_utils.py"
)
vc_utils = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vc_utils)


class DummyContractNotRevoked:
    address = "0x0000000000000000000000000000000000000000"

    class functions:
        @staticmethod
        def isVCRevoked(_):
            class Func:
                def call(self):
                    return False
            return Func()


class DummyContractRevoked:
    address = DummyContractNotRevoked.address

    class functions:
        @staticmethod
        def isVCRevoked(_):
            class Func:
                def call(self):
                    return True
            return Func()


def _stub_key():
    mock_key = MagicMock()
    mock_key.verify.return_value = None
    return mock_key


VC_TEMPLATE = {
    "id": "vc:test:1",
    "issuer": "did:local:test",
    "contractAddress": DummyContractNotRevoked.address,
    "proof": {
        "jws": "AAA",
        "verificationMethod": {"publicKeyPem": "-----BEGIN PUBLIC KEY-----\nAA\n-----END PUBLIC KEY-----"},
    },
}


def test_verify_vc_not_revoked():
    vc = VC_TEMPLATE.copy()
    with patch("vc_utils.serialization.load_pem_public_key", return_value=_stub_key()):
        result = vc_utils.verify_vc(vc, DummyContractNotRevoked())
    assert result == {
        "valid": True,
        "issuer": "did:local:test",
        "revoked": False,
        "status": "✅ Signature valid",
    }


def test_verify_vc_revoked():
    vc = VC_TEMPLATE.copy()
    with patch("vc_utils.serialization.load_pem_public_key", return_value=_stub_key()):
        result = vc_utils.verify_vc(vc, DummyContractRevoked())
    assert result == {
        "valid": False,
        "issuer": "did:local:test",
        "revoked": True,
        "status": "❌ Revoked",
    }
