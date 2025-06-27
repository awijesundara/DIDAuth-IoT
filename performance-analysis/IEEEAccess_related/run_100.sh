#!/bin/bash

for i in {1..100}
do
  echo "🔁 Running test $i of 100..."
  ./speed-test.sh
  sleep 1
done

echo "✅ All 100 tests completed. Results saved to speedtest_log.csv"
