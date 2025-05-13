#!/bin/bash

SERVER_PORT=8009
DURATION=300
OUTPUT="results.csv"
BIN_DIR="./built_bins"
LOG_DIR="./logs"

mkdir -p "$LOG_DIR"

echo "client_version,server_version,datagrams" > "$OUTPUT"

QUINN_VERSIONS=("0.11.7" "0.11.8")
PROTO_VERSIONS=("0.11.10" "0.11.11" "0.11.12")

for client_qv in "${QUINN_VERSIONS[@]}"; do
  for client_pv in "${PROTO_VERSIONS[@]}"; do
    CLIENT_BIN="${BIN_DIR}/client_${client_qv}_${client_pv}"

    for server_qv in "${QUINN_VERSIONS[@]}"; do
      for server_pv in "${PROTO_VERSIONS[@]}"; do
        SERVER_BIN="${BIN_DIR}/server_${server_qv}_${server_pv}"

        if [[ ! -x "$CLIENT_BIN" || ! -x "$SERVER_BIN" ]]; then
          echo "Skipping missing combo: $CLIENT_BIN / $SERVER_BIN"
          continue
        fi

        echo "🚀 Running: client=$client_qv/$client_pv  server=$server_qv/$server_pv"

        # Start server in background
        RUST_LOG=info "$SERVER_BIN" \
          --listen 0.0.0.0:$SERVER_PORT \
          --receive-window-size 630784000 \
          --max-concurrent-streams 512000 \
          --stream-receive-window-size 1232 \
          > "$LOG_DIR/server_${server_qv}_${server_pv}.log" 2>&1 &

        SERVER_PID=$!

        # Give server a moment to start
        sleep 2

        CLIENT_LOG_FILE="$LOG_DIR/client_${client_qv}_${client_pv}__${server_qv}_${server_pv}.log"


        "$CLIENT_BIN" \
            --target 127.0.0.1:$SERVER_PORT \
            --duration $DURATION \
            --num-connections 1 \
        > "$CLIENT_LOG_FILE" 2>&1


        # Stop server
        kill $SERVER_PID
        wait $SERVER_PID 2>/dev/null

        # Extract datagrams from log file
        DATAGRAMS=$(grep -o 'datagrams: [0-9]\+' "$CLIENT_LOG_FILE" | head -n1 | awk '{print $2}')

        echo "${client_qv}_${client_pv},${server_qv}_${server_pv},${DATAGRAMS}" >> "$OUTPUT"
        echo "📊 datagrams: $DATAGRAMS"
      done
    done
  done
done

echo "✅ All done. Results saved in $OUTPUT"

