#!/bin/bash

read -p "Enter the number of test cycles to run: " CYCLES

DATE_TAG=$(date +'%Y%m%d')
LOG_FILE="speedtest_payload_log_${DATE_TAG}.csv"

for ((i = 1; i <= CYCLES; i++))
do
  echo "🔁 Running test $i of $CYCLES..."
  ./analyze.sh
  sleep 1
done

echo "✅ All $CYCLES tests completed. Results saved to $LOG_FILE"
