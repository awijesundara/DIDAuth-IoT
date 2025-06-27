# DID IoT Firmware

This directory contains an example ESP32 sketch that uploads a verifiable credential and asks a gateway to verify it using Dilithium signatures.

## Usage

1. Open `esp32_fw.ino` in the Arduino IDE or PlatformIO.
2. Set `staSSID` and `staPassword` with your Wi-Fi credentials.
3. Update `verificationURL` with the URL of the gateway's `/vp/verify` endpoint.
4. Compile and flash the sketch to an ESP32.

The device starts in access point mode as `ESP32-VC-Uploader`. Connect to the network and visit the printed IP address to upload a `vc.json` file. After uploading, the device connects to Wi-Fi and posts a verifiable presentation to the gateway. You can delete the credential at `http://<device_ip>/delete`.
