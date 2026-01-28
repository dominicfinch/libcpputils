#!/usr/bin/env bash
set -euo pipefail

UPLOAD_DIR=/tmp/uploads
mkdir -p "$UPLOAD_DIR"

echo "[broker] Storage broker starting..."

# Very simple RPC-like interface via stdin/stdout
# In production you'd wrap this with grpc-gateway or gRPC in Go/Python

handle_start_upload() {
  local upload_id="$1"
  local bucket="$2"
  local object="$3"

  local pipe="$UPLOAD_DIR/$upload_id.pipe"
  mkfifo "$pipe"

  echo "[broker] Starting upload $upload_id -> gs://$bucket/$object"

  gsutil -o GSUtil:resumable_threshold=1M \
         cp "$pipe" "gs://$bucket/$object" &

  echo "$pipe"
}

handle_write_chunk() {
  local pipe="$1"
  cat >> "$pipe"
}

handle_finalize_upload() {
  local pipe="$1"
  rm -f "$pipe"
  echo "[broker] Upload complete"
}

# Demo mode: read raw stream from stdin and upload
if [[ "${1:-}" == "pipe" ]]; then
  UPLOAD_ID="$2"
  BUCKET="$3"
  OBJECT="$4"

  PIPE=$(handle_start_upload "$UPLOAD_ID" "$BUCKET" "$OBJECT")
  cat | handle_write_chunk "$PIPE"
  handle_finalize_upload "$PIPE"
fi
