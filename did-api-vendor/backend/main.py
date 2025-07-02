from fastapi import FastAPI, HTTPException, Request, Header
from pydantic import BaseModel
import os, json, requests, logging, base64
from pathlib import Path
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from web3 import Web3
from vc_utils import (
    issue_vc, verify_vc, revoke_vc, load_or_create_keys,
    save_api_key, verify_api_key, ipfs_download,
    sanitize_name, VC_DIR_TEMPLATE
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

load_dotenv()

DEFAULT_LOG_PATH = "/var/log/did-auth.log"
FALLBACK_LOG_PATH = Path(__file__).resolve().parent / "logs" / "did-auth.log"
LOG_PATH = os.getenv("LOG_PATH", DEFAULT_LOG_PATH)

def _create_handler(path: str | Path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return RotatingFileHandler(path, maxBytes=1_048_576, backupCount=5)

try:
    handler = _create_handler(LOG_PATH)
except PermissionError:
    handler = _create_handler(FALLBACK_LOG_PATH)
    LOG_PATH = str(FALLBACK_LOG_PATH)
    print(f"WARNING: falling back to {LOG_PATH} for logging")

formatter = logging.Formatter('[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
if not any(isinstance(h, RotatingFileHandler) and h.baseFilename == handler.baseFilename for h in logger.handlers):
    logger.addHandler(handler)

def _require_env(var: str) -> str:
    val = os.getenv(var)
    if not val:
        raise RuntimeError(f"{var} environment variable is required")
    return val

app = FastAPI()


@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    logger.info("%s %s -> %s", request.method, request.url.path, response.status_code)
    return response

                                
rpc_url = os.getenv("ARB_SEPOLIA_RPC") or os.getenv("ARBITRUM_RPC_URL")
if not rpc_url:
    raise RuntimeError("ARB_SEPOLIA_RPC or ARBITRUM_RPC_URL environment variable is required")
eth_private_key = _require_env("PRIVATE_KEY")
contract_addr_env = _require_env("CONTRACT_ADDRESS")
w3 = Web3(Web3.HTTPProvider(rpc_url))
account = w3.eth.account.from_key(eth_private_key)
contract_address = Web3.to_checksum_address(contract_addr_env)

with open("contract_abi.json") as f:
    abi = json.load(f)
contract = w3.eth.contract(address=contract_address, abi=abi)

                                                            
IPFS_API_URL = os.getenv("IPFS_API_URL", "http://127.0.0.1:5001/api/v0")
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

                
class DIDRequest(BaseModel):
    name: str
    metadata: str = ""

class VCRequest(BaseModel):
    did_name: str
    firmware_version: str
    device_model: str
    firmware_content: str          

class VCRevokeRequest(BaseModel):
    did_name: str
    vc_id: str

class VPCreateRequest(BaseModel):
    did_name: str
    firmware_version: str

                   
@app.post("/did/register")
def register_did(req: DIDRequest):
    did = f"did:local:{req.name}"
    private_key, pubkey_pem = load_or_create_keys(req.name)
    api_key = save_api_key(req.name)

                         
    did_doc = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": f"{did}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyPem": pubkey_pem
        }],
        "authentication": [f"{did}#key-1"]
    }

                  
    vendor_dir = os.path.join(DATA_DIR, "vendors", req.name)
    os.makedirs(vendor_dir, exist_ok=True)
    with open(os.path.join(vendor_dir, f"{req.name}_did.json"), "w") as f:
        json.dump(did_doc, f)

                    
    did_path = os.path.join(vendor_dir, f"{req.name}_did.json")
    with open(did_path, "rb") as f:
        res = requests.post(f"{IPFS_API_URL}/add", files={"file": f})
    if res.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to upload DID to IPFS")
    cid = res.json()["Hash"]

                       
    nonce = w3.eth.get_transaction_count(account.address)
    txn = contract.functions.registerDID(did, cid).build_transaction({
        "from": account.address,
        "nonce": nonce,
        "gas": 1000000,
        "maxFeePerGas": w3.to_wei("2", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("1", "gwei")
    })
    signed = w3.eth.account.sign_transaction(txn, eth_private_key)
    try:
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise HTTPException(status_code=500, detail="Blockchain transaction failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Blockchain error: {e}")

    return {
        "status": "✅ DID registered",
        "did": did,
        "ipfs_cid": cid,
        "tx": w3.to_hex(tx_hash),
        "api_key": api_key
    }

@app.post("/did/create")
def did_create(req: DIDRequest):
    return register_did(req)

@app.get("/did/resolve/{did_name}")
def resolve_did(did_name: str):
    did = f"did:local:{did_name}"
    cid = contract.functions.getDIDCID(did).call()
    response = requests.post(f"{IPFS_API_URL}/cat?arg={cid}")
    if response.status_code == 200:
        return json.loads(response.content)
    raise HTTPException(status_code=404, detail="DID not found")

@app.post("/vc/issue")
def vc_issue(req: VCRequest, x_api_key: str = Header(...)):
    if not verify_api_key(req.did_name, x_api_key):
        raise HTTPException(status_code=403, detail="❌ Invalid API Key")
    result = issue_vc(req.did_name, req.firmware_version, req.device_model, req.firmware_content)
    vc_id = result["vc"]["id"]
    did = result["vc"]["issuer"]
    nonce = w3.eth.get_transaction_count(account.address)
    txn = contract.functions.recordVC(vc_id, did).build_transaction({
        "from": account.address,
        "nonce": nonce,
        "gas": 1000000,
        "maxFeePerGas": w3.to_wei("2", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("1", "gwei")
    })
    signed = w3.eth.account.sign_transaction(txn, eth_private_key)
    try:
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise HTTPException(status_code=500, detail="Blockchain transaction failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Blockchain error: {e}")
    result["tx"] = w3.to_hex(tx_hash)
    return result

@app.post("/vp/create")
def vp_create(req: VPCreateRequest, x_api_key: str = Header(...)):
    did_name = sanitize_name(req.did_name)
    if not verify_api_key(did_name, x_api_key):
        raise HTTPException(status_code=403, detail="❌ Invalid API Key")

    vc_dir = VC_DIR_TEMPLATE.format(did_name=did_name, version=req.firmware_version)
    vc_path = os.path.join(vc_dir, "firmware_vc.json")
    if not os.path.exists(vc_path):
        raise HTTPException(status_code=404, detail="VC not found")

    with open(vc_path) as f:
        vc = json.load(f)

    vp = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [vc],
        "holder": f"did:local:{did_name}"
    }

    if os.getenv("SIGN_VP"):
        private_key, pubkey_pem = load_or_create_keys(did_name)
        message = json.dumps(vp, separators=(",", ":"), sort_keys=True).encode()
        signature = private_key.sign(message)
        vp["proof"] = {
            "type": "Ed25519Signature2020",
            "verificationMethod": {
                "id": f"did:local:{did_name}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": f"did:local:{did_name}",
                "publicKeyPem": pubkey_pem,
            },
            "jws": base64.urlsafe_b64encode(signature).decode(),
        }

    os.makedirs(vc_dir, exist_ok=True)
    with open(os.path.join(vc_dir, "presentation.json"), "w") as f:
        json.dump(vp, f, indent=2)

    return {"status": "✅ VP created", "vp": vp}

@app.post("/vc/verify")
async def vc_verify(request: Request):
    data = await request.json()
    if "cid" in data and "proof" not in data:
        try:
            vc = ipfs_download(data["cid"])
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        vc = data
    return verify_vc(vc, contract)

@app.post("/vp/verify")
async def vp_verify(request: Request):
    data = await request.json()

    vp = data.get("vp", data)
    vc_list = vp.get("verifiableCredential", [])
    if not vc_list:
        raise HTTPException(status_code=400, detail="VC missing from VP")
    vc = vc_list[0]
    vp_copy = vp.copy()
    proof = vp_copy.pop("proof", None)
    vp_valid = None
    if proof:
        holder = vp_copy.get("holder", "").split(":")[-1]
        _, pubkey_pem = load_or_create_keys(holder)
        public_key = serialization.load_pem_public_key(pubkey_pem.encode())
        message = json.dumps(vp_copy, separators=(",", ":"), sort_keys=True).encode()
        try:
            signature = base64.urlsafe_b64decode(proof["jws"] + "==")
            public_key.verify(signature, message)
            vp_valid = True
        except InvalidSignature:
            vp_valid = False

    result = verify_vc(vc, contract)
    result["vp_signature_valid"] = vp_valid
    if vp_valid is False:
        result["valid"] = False
        result["status"] = "❌ Invalid VP signature"
    return result

@app.post("/vc/revoke")
def vc_revoke(req: VCRevokeRequest, x_api_key: str = Header(...)):
    if not verify_api_key(req.did_name, x_api_key):
        raise HTTPException(status_code=403, detail="❌ Invalid API Key")
    tx_hash = revoke_vc(req.vc_id, w3, contract, account, eth_private_key)

    return {"status": "✅ VC revoked", "tx": tx_hash}



