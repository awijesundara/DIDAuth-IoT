#!/bin/bash

API="https://did.wijesundara.com"
NOW=$(date +"%Y-%m-%d %H:%M:%S")
LOG_FILE="speedtest_payload_log.csv"

if [ ! -f "$LOG_FILE" ]; then
  echo "timestamp,payload_size,did_time,vc_time,revoke_time" > "$LOG_FILE"
fi

for SIZE in 100 200 300 400 500
do
  echo ""
  echo "📦 Testing payload size: $SIZE characters..."

  RAW_PAYLOAD=$(head -c $SIZE < /dev/zero | tr '\0' 'A')
  FIRMWARE_CONTENT=$(echo -n "$RAW_PAYLOAD" | base64)

  VENDOR="SpeedTestVendor_${SIZE}_$(date +%s)"

  echo "📡 Registering DID..."
  START=$(date +%s.%N)
  REGISTER=$(curl -s -X POST $API/did/register -H "Content-Type: application/json" -d "{\"name\": \"$VENDOR\", \"metadata\": \"payload test $SIZE\"}")
  END=$(date +%s.%N)
  API_KEY=$(echo $REGISTER | jq -r .api_key)
  DID_TIME=$(echo "$END - $START" | bc)

  echo "🔐 Creating VC..."
  START=$(date +%s.%N)
  VC=$(curl -s -X POST $API/vc/issue -H "Content-Type: application/json" -H "x-api-key: $API_KEY" -d "{\"did_name\": \"$VENDOR\", \"firmware_version\": \"1.0.0\", \"device_model\": \"ESP32\", \"firmware_content\": \"$FIRMWARE_CONTENT\"}")
  END=$(date +%s.%N)
  VC_TIME=$(echo "$END - $START" | bc)

  echo "❌ Revoking VC..."
  START=$(date +%s.%N)
  REVOKE=$(curl -s -X POST $API/vc/revoke -H "Content-Type: application/json" -H "x-api-key: $API_KEY" -d "{\"did_name\": \"$VENDOR\", \"vc_id\": \"vc:$VENDOR:1.0.0\"}")
  END=$(date +%s.%N)
  REVOKE_TIME=$(echo "$END - $START" | bc)

  echo "=== ✅ RESULT FOR $SIZE chars ==="
  echo "DID: $DID_TIME s | VC: $VC_TIME s | REVOKE: $REVOKE_TIME s"

  echo "$NOW,$SIZE,$DID_TIME,$VC_TIME,$REVOKE_TIME" >> "$LOG_FILE"
done

echo "✅ All tests complete. Logged to $LOG_FILE"
