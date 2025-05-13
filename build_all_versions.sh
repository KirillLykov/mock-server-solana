#!/bin/bash

set -e

QUINN_VERSIONS=("0.11.7" "0.11.8")
PROTO_VERSIONS=("0.11.10" "0.11.11" "0.11.12")
OUTPUT_DIR="./built_bins"
SERVER_BIN="server"
CLIENT_BIN="client"

mkdir -p "$OUTPUT_DIR"

for qv in "${QUINN_VERSIONS[@]}"; do
  for pv in "${PROTO_VERSIONS[@]}"; do
    echo "🔧 Building with quinn=$qv, quinn-proto=$pv..."

    # Generate Cargo.toml from template
    sed \
      -e "s/__QUINN_VERSION__/$qv/" \
      -e "s/__PROTO_VERSION__/$pv/" \
      Cargo.toml.template > Cargo.toml

    cargo clean
    if cargo build --release; then
      echo "✅ Build succeeded for $qv / $pv"
      cp "target/release/$SERVER_BIN" "$OUTPUT_DIR/${SERVER_BIN}_${qv}_${pv}"
      cp "target/release/$CLIENT_BIN" "$OUTPUT_DIR/${CLIENT_BIN}_${qv}_${pv}"
    else
      echo "❌ Build failed for quinn=$qv / quinn-proto=$pv"
    fi
  done
done

echo "🎉 Done. Binaries in $OUTPUT_DIR"

