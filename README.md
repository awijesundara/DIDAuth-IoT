# DIDAuth-IoT

DIDAuth-IoT explores decentralized firmware verification for IoT devices. The project combines two FastAPI backends and an ESP32 example that demonstrate how verifiable credentials can secure firmware updates.

## Repository layout

- **did-api-vendor** – backend that issues credentials using a blockchain and IPFS
- **did-api-gateway** – lightweight gateway used for local verification
- **did-iot-firmware** – ESP32 sketch that uploads and verifies a credential
- **performance-analysis** – scripts to measure latency of the workflow

Each directory contains a README with setup details and example commands.

## License
© 2025 Anushka Wijesundara - Institute of Science Tokyo, Japan
