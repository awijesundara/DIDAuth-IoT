#DID API Vendor

This backend issues and manages verifiable credentials using a DID registry smart contract and IPFS. It is intended for the organization that signs firmware updates.

## Prerequisites

- Python 3.10 or later
- Node.js with npm
- Access to an Arbitrum Sepolia RPC endpoint
- IPFS daemon or hosted gateway
- The `pqcrypto` Python package

## Setup

1. Copy `backend/.env.example` to `backend/.env` and fill in the values for
   `CONTRACT_ADDRESS`, `PRIVATE_KEY`, `FERNET_SECRET` and either
   `ARB_SEPOLIA_RPC` or `ARBITRUM_RPC_URL`. Optionally set `IPFS_API_URL`.
   You can generate a Fernet secret with:

   ```bash
   python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
   ```
2. Install dependencies and start the server:

```bash
cd backend
./setup.sh
ipfs daemon &  # skip if using a hosted IPFS endpoint
./run.sh
```

To run in Docker:

```bash
cd backend
docker build -t did-vendor .
docker run --env-file .env -p 8000:8000 did-vendor
```

## Logging

Requests and errors are written to `/var/log/did-auth.log` by default. Set the
`LOG_PATH` environment variable to change the location. If the server cannot
write to `/var/log`, create the log file once as root and grant ownership:

```bash
sudo touch /var/log/did-auth.log
sudo chown $USER:$USER /var/log/did-auth.log
```

The log file rotates at 1&nbsp;MB with up to five backups.

## API overview

Typical interaction with `curl`:

```bash
# register a DID
curl -X POST http://localhost:8000/did/register \
     -H "Content-Type: application/json" \
     -d '{"name": "vendor1"}'

# issue a credential
curl -X POST http://localhost:8000/vc/issue \
     -H "X-API-Key: <api_key>" \
     -H "Content-Type: application/json" \
     -d '{"did_name": "vendor1", "firmware_version": "1.0.0", "device_model": "ESP32", "firmware_content": "<base64>"}'

# verify the credential
curl -X POST http://localhost:8000/vc/verify \
     -H "Content-Type: application/json" \
     -d '{"cid": "<cid>"}'
```

The `/vp/create` endpoint builds a presentation from a stored credential but
does not sign it. Set the `SIGN_VP` environment variable if you want the server
to attach a Dilithium signature.
