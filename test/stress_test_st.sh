while true; do
  curl -k --max-time 5 --silent --output /dev/null https://localhost:4433 || echo "Request failed"
  sleep 0.1  # 100ms interval
done
