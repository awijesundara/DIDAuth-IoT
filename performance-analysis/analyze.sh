#!/bin/bash

API="https://did.wijesundara.com"
DATE_TAG=$(date +'%Y%m%d')
LOG_FILE="speedtest_payload_log_${DATE_TAG}.csv"

if [ ! -f "$LOG_FILE" ]; then
  echo "timestamp,payload_size,did_time,vc_time,vp_time,verify_time,revoke_time,verify_revoked_time" > "$LOG_FILE"
fi

for SIZE in 100 200 300 400 500
do
  NOW=$(date +"%Y-%m-%d %H:%M:%S")
  echo "[RUNNING] Payload size: $SIZE"

  RAW_PAYLOAD=$(head -c $SIZE < /dev/zero | tr '\0' 'A')
  FIRMWARE_CONTENT=$(echo -n "$RAW_PAYLOAD" | base64)
  VENDOR="SpeedTestVendor_${SIZE}_$(date +%s)"

  echo "[STEP] Registering DID"
  START=$(date +%s.%N)
  REGISTER=$(curl -s -X POST $API/did/register -H "Content-Type: application/json" \
    -d "{\"name\": \"$VENDOR\"}")
  END=$(date +%s.%N)
  API_KEY=$(echo $REGISTER | jq -r .api_key)
  DID_TIME=$(echo "$END - $START" | bc)

  echo "[STEP] Creating VC"
  START=$(date +%s.%N)
  VC=$(curl -s -X POST $API/vc/issue -H "Content-Type: application/json" -H "x-api-key: $API_KEY" \
    -d "{\"did_name\": \"$VENDOR\", \"firmware_version\": \"1.0.0\", \"device_model\": \"ESP32\", \"firmware_content\": \"$FIRMWARE_CONTENT\"}")
  END=$(date +%s.%N)
  VC_TIME=$(echo "$END - $START" | bc)

  echo "[STEP] Creating VP"
  START=$(date +%s.%N)
  VP=$(curl -s -X POST $API/vp/create -H "Content-Type: application/json" -H "x-api-key: $API_KEY" \
    -d "{\"did_name\": \"$VENDOR\", \"vc_ids\": [\"vc:$VENDOR:1.0.0\"]}")
  END=$(date +%s.%N)
  VP_TIME=$(echo "$END - $START" | bc)
  VP_JWT=$(echo "$VP" | jq -r .vp_jwt)

  echo "[STEP] Verifying VP"
  START=$(date +%s.%N)
  VERIFY=$(curl -s -X POST $API/vp/verify -H "Content-Type: application/json" \
    -d "{\"vp_jwt\": \"$VP_JWT\"}")
  END=$(date +%s.%N)
  VERIFY_TIME=$(echo "$END - $START" | bc)

  echo "[STEP] Revoking VC"
  START=$(date +%s.%N)
  REVOKE=$(curl -s -X POST $API/vc/revoke -H "Content-Type: application/json" -H "x-api-key: $API_KEY" \
    -d "{\"did_name\": \"$VENDOR\", \"vc_id\": \"vc:$VENDOR:1.0.0\"}")
  END=$(date +%s.%N)
  REVOKE_TIME=$(echo "$END - $START" | bc)

  echo "[STEP] Verifying revoked VP"
  START=$(date +%s.%N)
  VERIFY_REVOKED=$(curl -s -X POST $API/vp/verify -H "Content-Type: application/json" \
    -d "{\"vp_jwt\": \"$VP_JWT\"}")
  END=$(date +%s.%N)
  VERIFY_REVOKED_TIME=$(echo "$END - $START" | bc)

  echo "[RESULT] $SIZE bytes -> DID:$DID_TIME VC:$VC_TIME VP:$VP_TIME VERIFY:$VERIFY_TIME REVOKE:$REVOKE_TIME VERIFY_REVOKED:$VERIFY_REVOKED_TIME"
  echo "$NOW,$SIZE,$DID_TIME,$VC_TIME,$VP_TIME,$VERIFY_TIME,$REVOKE_TIME,$VERIFY_REVOKED_TIME" >> "$LOG_FILE"
done

echo "[FINISHED] Logged to $LOG_FILE"
