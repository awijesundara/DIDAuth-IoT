import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

spec = importlib.util.spec_from_file_location(
    "vc_utils", Path(__file__).resolve().parents[1] / "backend" / "vc_utils.py"
)
vc_utils = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vc_utils)

class DummyContract:
    address = "0x0000000000000000000000000000000000000000"
    class functions:
        @staticmethod
        def isVCRevoked(_):
            class Func:
                def call(self):
                    return False
            return Func()

def test_verify_vc_missing_contract_address():
    vc = {
        "id": "vc:test:1",
        "issuer": "did:local:test",
        "proof": {"jws": "sig", "verificationMethod": {"publicKeyBase64": "aGk="}} ,
    }
    result = vc_utils.verify_vc(vc, DummyContract())
    assert result == {"valid": False, "error": "contractAddress missing"}


def test_revoke_vc_sends_transaction():
    mock_w3 = MagicMock()
    mock_w3.eth.get_transaction_count.return_value = 1
    mock_w3.to_wei.return_value = 1
    signed = MagicMock()
    signed.raw_transaction = b"raw"
    mock_w3.eth.account.sign_transaction.return_value = signed
    mock_w3.eth.send_raw_transaction.return_value = b"hash"
    mock_w3.eth.wait_for_transaction_receipt.return_value = MagicMock(status=1)
    mock_w3.to_hex.return_value = "0xhash"

    mock_contract = MagicMock()
    mock_contract.functions.revokeVC.return_value.build_transaction.return_value = {}

    mock_account = MagicMock()
    mock_account.address = "0x0"

    tx = vc_utils.revoke_vc("vc1", mock_w3, mock_contract, mock_account, "key")

    assert tx == "0xhash"
    mock_w3.eth.send_raw_transaction.assert_called_once_with(signed.raw_transaction)


def test_issue_vc_uploads_firmware_and_embeds_cid(monkeypatch):
    calls = []

    class MockResp:
        def __init__(self, cid):
            self.status_code = 200
            self._cid = cid

        def json(self):
            return {"Hash": self._cid}

    def mock_post(url, files=None):
        calls.append((url, files))
        if len(calls) == 1:
            return MockResp("fwcid")
        return MockResp("vccid")

    class DummyKey:
        def sign(self, _):
            return b"sig"

    monkeypatch.setattr(vc_utils, "requests", MagicMock(post=mock_post))
    monkeypatch.setattr(vc_utils, "load_or_create_keys", lambda _: (DummyKey(), b"pub"))

    res = vc_utils.issue_vc("test", "1.0", "ESP32", base64.b64encode(b"bin").decode())

    assert res["firmware_cid"] == "fwcid"
    assert res["ipfs_cid"] == "vccid"
    assert res["vc"]["firmwareCid"] == "fwcid"
    assert len(calls) == 2

