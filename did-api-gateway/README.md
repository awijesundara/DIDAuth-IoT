# DID API Gateway

This lightweight backend verifies credentials locally without requiring a blockchain. It stores DID documents on disk and downloads credentials from IPFS, so it can run completely offline.

The gateway requires an Arbitrum RPC endpoint and the address of the
`DIDRegistry` smart contract in order to resolve DID documents and check VC
revocation.  Set the environment variables `ARB_SEPOLIA_RPC` (or
`ARBITRUM_RPC_URL`) and `CONTRACT_ADDRESS` so the server can reach the chain.
Without these values the server will still run but only performs local signature
checks.

## Requirements

- Python 3.10 or later
- An `AES_KEY` used for signing and verifying data
- `ARB_SEPOLIA_RPC`/`ARBITRUM_RPC_URL` and `CONTRACT_ADDRESS` so the gateway can
  query the DID registry
- Optional `IPFS_API_URL` to override the default `https://ipfs.io` endpoint

## Running

1. Copy `.env.example` to `.env` and set `AES_KEY`, `ARB_SEPOLIA_RPC` (or
   `ARBITRUM_RPC_URL`) and `CONTRACT_ADDRESS`. Optionally define
   `IPFS_API_URL` to override the default IPFS endpoint. You can generate a key
   with:

```bash
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

2. Start the server using `uvicorn` or the helper scripts:

```bash
uvicorn did_vc_api:app --reload
```

or

```bash
./setup.sh
./run.sh
```

## Logging

Requests and errors are stored in `/var/log/did-auth.log` by default. Set the
`LOG_PATH` environment variable if you need to log elsewhere. If your user
cannot write to `/var/log`, create the file once as root and change its
ownership, for example:

```bash
sudo touch /var/log/did-auth.log
sudo chown $USER:$USER /var/log/did-auth.log
```

The log rotates when it reaches 1&nbsp;MB and keeps five backups.

## Sample workflow

```bash
# create a DID
token=$(curl -s -X POST http://localhost:8000/did/create \
    -H "Content-Type: application/json" -d '{"name":"gw"}' | jq -r '.api_key')

# issue a credential
curl -X POST http://localhost:8000/vc/create \
     -H "X-API-Key: $token" \
     -H "Content-Type: application/json" \
     -d '{"did_name":"gw","firmware_version":"1","firmware_content":"<base64>"}'

# create a presentation and verify it
curl -X POST http://localhost:8000/vp/create \
     -H "X-API-Key: $token" \
     -H "Content-Type: application/json" \
     -d '{"did_name":"gw","firmware_version":"1"}' > vp.json

curl -X POST http://localhost:8000/vp/verify \
     -H "Content-Type: application/json" \
     -d @vp.json
```

`/vp/create` generates an unsigned presentation that simply bundles the
credential. Set the `SIGN_VP` environment variable to sign the presentation with
the holder's Ed25519 key. Alternatively you can sign the JSON yourself and
include the signature in a `proof` field.

The gateway can also verify individual credentials via `/vc/verify`.

Because DID documents and revocation status live on-chain, both `/vc/verify` and
`/vp/verify` require the RPC endpoint and contract address described above. If
they are missing, only the signature is checked and revocation cannot be
detected.
