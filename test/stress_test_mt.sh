#!/bin/bash

set -euo pipefail

THREADS=10
REQUESTS_PER_THREAD=100

rm -f result.log rtt.log

# Subtask function: each thread accesses N times
function test_worker() {
    for i in $(seq 1 $REQUESTS_PER_THREAD); do
        start=$(date +%s%3N)
        if curl -k --max-time 5 --silent --output /dev/null https://localhost:4433; then
            echo OK
        else
            echo FAIL
        fi
        end=$(date +%s%3N)
        echo $((end - start)) >&3
    done
}

echo "🚀 Launching $THREADS threads × $REQUESTS_PER_THREAD requests..."

# Start concurrent tasks
for i in $(seq 1 $THREADS); do
    {
        exec 3>> rtt.log      # Each subtask appends RTT to rtt.log
        test_worker
    } >> result.log &
done

wait

# ✅ Summary Statistics
success=$(grep -c OK result.log || true)
fail=$(grep -c FAIL result.log || true)
total=$((success + fail))

echo "✅ Success: $success"
echo "❌ Failed:  $fail"
echo "📦 Total:   $total"

echo "📊 Average RTT (ms):"
awk '{sum+=$1} END {if(NR>0) print sum/NR; else print "N/A"}' rtt.log

echo "🔺 Max / 🔻 Min RTT (ms):"
awk 'NR==1{min=max=$1} {if($1>max)max=$1; if($1<min)min=$1} END {print "Max:", max, "Min:", min}' rtt.log

