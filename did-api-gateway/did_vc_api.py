from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import JSONResponse
import binascii, logging
from logging.handlers import RotatingFileHandler
from pydantic import BaseModel
from pqcrypto.sign import dilithium2
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from web3 import Web3
import json, os, base64, datetime, hashlib, uuid, re
import requests
import httpx
from pathlib import Path

                                            
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

                                    
_aes_env = os.getenv("AES_KEY")
if not _aes_env:
    raise RuntimeError("AES_KEY environment variable is required")
try:
    FERNET = Fernet(_aes_env)
    AES_KEY_LEGACY = base64.b64decode(_aes_env)
    if len(AES_KEY_LEGACY) != 32:
        raise ValueError
except Exception as e:
    raise RuntimeError("Invalid AES_KEY environment variable") from e

app = FastAPI()


@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    logger.info("%s %s -> %s", request.method, request.url.path, response.status_code)
    return response

DATA_DIR = "data"
DID_DIR_TEMPLATE = os.path.join(DATA_DIR, "dids", "{name}")
VC_DIR_TEMPLATE = os.path.join(DATA_DIR, "vcs", "{did_name}", "{firmware_version}")
KEY_DIR = os.path.join(DATA_DIR, "api_keys")
REV_PATH = os.path.join(DATA_DIR, "revocations", "revoked.json")
RECORDED_VC_PATH = os.path.join(DATA_DIR, "revocations", "recorded_vcs.json")

os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(os.path.dirname(REV_PATH), exist_ok=True)
os.makedirs(os.path.dirname(RECORDED_VC_PATH), exist_ok=True)

                     
ARBITRUM_RPC_URL = os.getenv("ARBITRUM_RPC_URL") or os.getenv("ARB_SEPOLIA_RPC")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
ABI_PATH = os.getenv("CONTRACT_ABI_PATH", "blockchain/contracts/DIDRegistry.json")
                                   
IPFS_API_URL = os.getenv("IPFS_API_URL", "https://ipfs.io")

if ARBITRUM_RPC_URL and CONTRACT_ADDRESS:
    with open(ABI_PATH) as f:
        contract_abi = json.load(f)
    w3 = Web3(Web3.HTTPProvider(ARBITRUM_RPC_URL))
    contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=contract_abi)
else:
    contract = None

def sanitize_name(name: str) -> str:
    if not re.match(r"^[A-Za-z0-9_-]+$", name):
        raise HTTPException(status_code=400, detail="Invalid name")
    return name

def validate_firmware_version(version: str) -> str:
    if not re.match(r"^[A-Za-z0-9._-]+$", version):
        raise HTTPException(status_code=400, detail="Invalid firmware version")
    return version

class DIDRequest(BaseModel):
    name: str

class VCCreateRequest(BaseModel):
    did_name: str
    firmware_version: str
    firmware_content: str                           

class VPCreateRequest(BaseModel):
    did_name: str
    firmware_version: str

class VCRevokeRequest(BaseModel):
    vc_id: str
    did_name: str

class VCVerifyRequest(BaseModel):
    cid: str

                              

def encrypt_key(key: str) -> str:
    return FERNET.encrypt(key.encode()).decode()

def decrypt_key(enc_key: str) -> str:
    return FERNET.decrypt(enc_key.encode()).decode()

def decrypt_key_legacy(enc_key: str) -> str:
    raw = base64.b64decode(enc_key)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(AES_KEY_LEGACY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

                    

def verify_api_key(did_name: str, x_api_key: str):
    did_name = sanitize_name(did_name)
    path = os.path.join(KEY_DIR, f"{did_name}.key")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="API key not found")
    encrypted_key = open(path).read().strip()
    try:
        stored = decrypt_key(encrypted_key)
    except InvalidToken:
                                        
        try:
            stored = decrypt_key_legacy(encrypted_key)
            with open(path, "w") as f:
                f.write(encrypt_key(stored))
        except Exception:
            raise HTTPException(status_code=403, detail="Invalid API key")
    if stored != x_api_key:
        raise HTTPException(status_code=403, detail="Invalid API key")

                      

@app.post("/did/create")
def create_did(req: DIDRequest):
    name = sanitize_name(req.name)
    did_path = DID_DIR_TEMPLATE.format(name=name)
    if os.path.exists(did_path):
        raise HTTPException(status_code=400, detail="DID already exists")
    os.makedirs(did_path, exist_ok=True)

    public_key, private_key = dilithium2.generate_keypair()

    with open(f"{did_path}/private_key.bin", "wb") as f:
        f.write(private_key)
    with open(f"{did_path}/public_key.bin", "wb") as f:
        f.write(public_key)

    did_doc = {
        "id": f"did:local:{name}",
        "verificationMethod": [{
            "id": f"did:local:{name}#key-1",
            "type": "DilithiumVerificationKey2020",
            "controller": f"did:local:{name}",
            "publicKeyBase64": base64.b64encode(public_key).decode()
        }]
    }
    with open(f"{did_path}/did.json", "w") as f:
        json.dump(did_doc, f, indent=2)

    api_key = str(uuid.uuid4())
    encrypted = encrypt_key(api_key)
    with open(os.path.join(KEY_DIR, f"{name}.key"), "w") as f:
        f.write(encrypted)

    return {"status": "✅ DID created", "did": did_doc, "api_key": api_key}

                     

@app.post("/vc/create")
def create_vc(req: VCCreateRequest, x_api_key: str = Header(...)):
    did_name = sanitize_name(req.did_name)
    firmware_version = validate_firmware_version(req.firmware_version)
    verify_api_key(did_name, x_api_key)

    did_path = DID_DIR_TEMPLATE.format(name=did_name)
    with open(f"{did_path}/private_key.bin", "rb") as f:
        private_key = f.read()

    try:
        firmware_bytes = base64.b64decode(req.firmware_content)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Invalid base64 data")
    firmware_hash = hashlib.sha256(firmware_bytes).hexdigest()

    vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "FirmwareCredential"],
        "id": f"vc:{did_name}:{firmware_version}",
        "issuer": f"did:local:{did_name}",
        "issuanceDate": datetime.datetime.utcnow().isoformat() + "Z",
        "credentialSubject": {
            "firmwareVersion": firmware_version,
            "firmwareHash": firmware_hash,
            "deviceModel": "ESP32"
        }
    }

    message = json.dumps(vc, separators=(",", ":"), sort_keys=True).encode()
    signature = dilithium2.sign(message, private_key)
    vc["proof"] = {
        "type": "DilithiumSignature2020",
        "verificationMethod": f"did:local:{did_name}#key-1",
        "jws": base64.urlsafe_b64encode(signature).decode()
    }

    vc_dir = VC_DIR_TEMPLATE.format(did_name=did_name, firmware_version=firmware_version)
    os.makedirs(vc_dir, exist_ok=True)
    with open(f"{vc_dir}/firmware_vc.json", "w") as f:
        json.dump(vc, f, indent=2)

    issued = []
    if os.path.exists(RECORDED_VC_PATH):
        try:
            issued = json.load(open(RECORDED_VC_PATH))
        except Exception:
            issued = []
    entry = {"id": vc["id"], "issuer": vc["issuer"]}
    if entry not in issued:
        issued.append(entry)
        with open(RECORDED_VC_PATH, "w") as f:
            json.dump(issued, f, indent=2)

    return {"status": "✅ VC created", "vc": vc}

                     

@app.post("/vp/create")
def create_vp(req: VPCreateRequest, x_api_key: str = Header(...)):
    did_name = sanitize_name(req.did_name)
    firmware_version = validate_firmware_version(req.firmware_version)
    verify_api_key(did_name, x_api_key)

    vc_dir = VC_DIR_TEMPLATE.format(did_name=did_name, firmware_version=firmware_version)
    vc_path = f"{vc_dir}/firmware_vc.json"
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
        did_path = DID_DIR_TEMPLATE.format(name=did_name)
        with open(f"{did_path}/private_key.bin", "rb") as f:
            private_key = f.read()
        pub_key = open(f"{did_path}/public_key.bin", "rb").read()
        message = json.dumps(vp, separators=(",", ":"), sort_keys=True).encode()
        signature = dilithium2.sign(message, private_key)
        vp["proof"] = {
            "type": "DilithiumSignature2020",
            "verificationMethod": {
                "id": f"did:local:{did_name}#key-1",
                "type": "DilithiumVerificationKey2020",
                "controller": f"did:local:{did_name}",
                "publicKeyBase64": base64.b64encode(pub_key).decode(),
            },
            "jws": base64.urlsafe_b64encode(signature).decode(),
        }

    with open(f"{vc_dir}/presentation.json", "w") as f:
        json.dump(vp, f, indent=2)

    return {"status": "✅ VP created", "vp": vp}

                         

@app.post("/vp/verify")
async def verify_vp(request: Request):

    vp_json = await request.json()

    if "verifiableCredential" in vp_json:
        vp = vp_json
    elif isinstance(vp_json.get("vp"), dict) and "verifiableCredential" in vp_json["vp"]:
        vp = vp_json["vp"]
    else:
        raise HTTPException(status_code=400, detail="Invalid VP payload")

    vp_copy = vp.copy()
    vp_proof = vp_copy.pop("proof", None)
    vp_sig_valid = None
    if vp_proof:
        holder = vp_copy.get("holder", "").split(":")[-1]
        did_path = f"{DID_DIR_TEMPLATE.format(name=holder)}/did.json"
        if not os.path.exists(did_path):
            if contract is None:
                raise HTTPException(status_code=500, detail="DID document not found")
            try:
                did_full = f"did:local:{holder}"
                cid = contract.functions.getDIDCID(did_full).call()
                async with httpx.AsyncClient() as client:
                    resp = await client.get(f"{IPFS_API_URL}/ipfs/{cid}")
                resp.raise_for_status()
                did_doc = resp.json()
                os.makedirs(os.path.dirname(did_path), exist_ok=True)
                with open(did_path, "w") as f:
                    json.dump(did_doc, f, indent=2)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to fetch DID: {str(e)}")
        else:
            with open(did_path) as f:
                did_doc = json.load(f)

        pubkey_b64 = did_doc["verificationMethod"][0]["publicKeyBase64"]
        public_key = base64.b64decode(pubkey_b64)
        message = json.dumps(vp_copy, separators=(",", ":"), sort_keys=True).encode()
        try:
            signature = base64.urlsafe_b64decode(vp_proof["jws"] + "==")
            dilithium2.verify(message, signature, public_key)
            vp_sig_valid = True
        except Exception:
            vp_sig_valid = False

    if "verifiableCredential" not in vp or not isinstance(vp["verifiableCredential"], list) or not vp["verifiableCredential"]:
        raise HTTPException(status_code=400, detail="Missing verifiableCredential in VP")

    vc = vp["verifiableCredential"][0]
    if not isinstance(vc, dict):
        raise HTTPException(status_code=400, detail="Invalid verifiableCredential format")
    if "issuer" not in vc:
        raise HTTPException(status_code=400, detail="Missing issuer in VC")
    if "proof" not in vc:
        raise HTTPException(status_code=400, detail="Missing proof in VC")

    vc = vc.copy()
    proof = vc.pop("proof")

    issuer_did = vc["issuer"].split(":")[-1]
    issuer_did = sanitize_name(issuer_did)
    did_path = f"{DID_DIR_TEMPLATE.format(name=issuer_did)}/did.json"
    if not os.path.exists(did_path):
        if contract is None:
            raise HTTPException(status_code=500, detail="DID document not found")
        try:
            did_full = f"did:local:{issuer_did}"
            cid = contract.functions.getDIDCID(did_full).call()
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{IPFS_API_URL}/ipfs/{cid}")
            resp.raise_for_status()
            did_doc = resp.json()
            os.makedirs(os.path.dirname(did_path), exist_ok=True)
            with open(did_path, "w") as f:
                json.dump(did_doc, f, indent=2)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to fetch DID: {str(e)}")
    else:
        with open(did_path) as f:
            did_doc = json.load(f)

    pubkey_b64 = did_doc["verificationMethod"][0]["publicKeyBase64"]
    public_key = base64.b64decode(pubkey_b64)

    message = json.dumps(vc, separators=(",", ":"), sort_keys=True).encode()
    signature = base64.urlsafe_b64decode(proof["jws"] + "==")

    try:
        dilithium2.verify(message, signature, public_key)
        valid = True
    except Exception:
        valid = False

    chain_issuer = None
    if contract is not None:
        try:
            chain_issuer = contract.functions.getVCIssuer(vc["id"]).call()
        except Exception:
            chain_issuer = ""
        if not chain_issuer:
            return {
                "valid_signature": False,
                "revoked": False,
                "status": "❌ VC not recorded — possibly forged",
            }

    if contract is None:
        revoked = json.load(open(REV_PATH)) if os.path.exists(REV_PATH) else []
        recorded = json.load(open(RECORDED_VC_PATH)) if os.path.exists(RECORDED_VC_PATH) else []
        is_revoked = vc["id"] in revoked
        was_issued = any(r.get("id") == vc["id"] for r in recorded)
    else:
        is_revoked = contract.functions.isVCRevoked(vc["id"]).call()
        was_issued = True

    firmware_ok = False
    firmware_cid = vc.get("firmwareCid")
    expected_hash = vc.get("credentialSubject", {}).get("firmwareHash")
    if firmware_cid and expected_hash:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{IPFS_API_URL}/ipfs/{firmware_cid}")
            resp.raise_for_status()
            data = resp.content
            digest = hashlib.sha256(data).hexdigest()
            firmware_ok = digest == expected_hash
        except Exception:
            firmware_ok = False

    status = (
        "❌ Invalid VP signature" if vp_sig_valid is False else
        "❌ Invalid VC signature" if not valid else
        "❌ VC is revoked" if is_revoked else
        "❌ VC never issued" if not was_issued else
        "✅ VP is valid"
    )

    return {
        "vp_signature_valid": vp_sig_valid,
        "valid_signature": valid,
        "revoked": is_revoked,
        "issued": was_issued,
        "firmware_hash_match": firmware_ok,
        "status": status,
    }

                         

@app.post("/vc/verify")
def verify_vc(req: VCVerifyRequest):
    cid = req.cid.strip()
    try:
        response = requests.get(f"{IPFS_API_URL}/ipfs/{cid}")
        response.raise_for_status()
        vc = response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IPFS fetch error: {str(e)}")

    if "issuer" not in vc:
        raise HTTPException(status_code=400, detail="Missing issuer in VC")
    issuer_did = vc.get("issuer", "").split(":")[-1]
    did_full = f"did:local:{issuer_did}"

    did_path = f"{DID_DIR_TEMPLATE.format(name=issuer_did)}/did.json"
    if contract is None:
        if not os.path.exists(did_path):
            raise HTTPException(status_code=500, detail="DID document not found")
        with open(did_path) as f:
            did_doc = json.load(f)
    else:
        if os.path.exists(did_path):
            with open(did_path) as f:
                did_doc = json.load(f)
        else:
            try:
                cid_from_chain = contract.functions.getDIDCID(did_full).call()
                did_response = requests.get(f"{IPFS_API_URL}/ipfs/{cid_from_chain}")
                did_response.raise_for_status()
                did_doc = did_response.json()
                os.makedirs(os.path.dirname(did_path), exist_ok=True)
                with open(did_path, "w") as f:
                    json.dump(did_doc, f, indent=2)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"DID fetch failed: {str(e)}")

    try:
        pubkey_b64 = did_doc["verificationMethod"][0]["publicKeyBase64"]
        public_key = base64.b64decode(pubkey_b64)
    except Exception:
        raise HTTPException(status_code=500, detail="Invalid public key in DID document")

    proof = vc.pop("proof", None)
    if not proof:
        raise HTTPException(status_code=400, detail="Missing proof in VC")

    message = json.dumps(vc, separators=(',', ':'), sort_keys=True).encode()
    try:
        signature = base64.urlsafe_b64decode(proof["jws"] + "==")
        dilithium2.verify(message, signature, public_key)
        valid = True
    except Exception:
        valid = False

    chain_issuer = None
    if contract is not None:
        try:
            chain_issuer = contract.functions.getVCIssuer(vc["id"]).call()
        except Exception:
            chain_issuer = ""
        if not chain_issuer:
            return {
                "valid_signature": False,
                "revoked": False,
                "status": "❌ VC not recorded — possibly forged",
            }

    if contract is None:
        revoked = json.load(open(REV_PATH)) if os.path.exists(REV_PATH) else []
        recorded = json.load(open(RECORDED_VC_PATH)) if os.path.exists(RECORDED_VC_PATH) else []
        is_revoked = vc["id"] in revoked
        was_issued = any(r.get("id") == vc["id"] for r in recorded)
    else:
        is_revoked = contract.functions.isVCRevoked(vc["id"]).call()
        was_issued = True

    return {
        "valid": valid and not is_revoked and was_issued,
        "issuer": did_full,
        "revoked": is_revoked,
        "issued": was_issued,
        "status": (
            "❌ Invalid Signature" if not valid else
            "❌ Revoked VC" if is_revoked else
            "❌ VC never issued" if not was_issued else
            "✅ Signature valid"
        )
    }

                       

@app.post("/vc/revoke")
def revoke_vc(req: VCRevokeRequest, x_api_key: str = Header(...)):
    did_name = sanitize_name(req.did_name)
    verify_api_key(did_name, x_api_key)
    revoked = json.load(open(REV_PATH)) if os.path.exists(REV_PATH) else []
    if req.vc_id not in revoked:
        revoked.append(req.vc_id)
    with open(REV_PATH, "w") as f:
        json.dump(revoked, f, indent=2)
    return {"status": "✅ VC revoked", "vc_id": req.vc_id}

