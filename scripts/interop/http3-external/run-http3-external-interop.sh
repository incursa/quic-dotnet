#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
ARTIFACTS_ROOT="${ARTIFACTS_ROOT:-.artifacts/http3-external}"
PLAN_ONLY=0
SKIP_BUILD=0
KEEP_SERVER=0

TARGETS=(
  "incursa-client__incursa-server"
  "curl__incursa-server"
  "aioquic-client__incursa-server"
  "quiche-client__incursa-server"
  "ngtcp2-client__incursa-server"
  "incursa-client__aioquic-server"
  "incursa-client__quiche-server"
  "incursa-client__ngtcp2-server"
)

SCENARIOS=(
  "get-small"
  "get-empty"
  "get-large"
  "multiple-concurrent-get"
  "not-found"
  "many-headers"
  "split-data"
  "request-cancellation"
  "goaway"
  "connection-close-in-flight"
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts-root)
      ARTIFACTS_ROOT="$2"
      shift 2
      ;;
    --compose-file)
      COMPOSE_FILE="$2"
      shift 2
      ;;
    --plan-only)
      PLAN_ONLY=1
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --keep-server-running)
      KEEP_SERVER=1
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ROOT="$REPO_ROOT/$ARTIFACTS_ROOT/$RUN_ID"
WWW_ROOT="$RUN_ROOT/www"
DOWNLOADS_ROOT="$RUN_ROOT/downloads"
CERT_ROOT="$RUN_ROOT/certs"
LOGS_ROOT="$RUN_ROOT/logs"
RESULTS_PATH="$RUN_ROOT/results.jsonl"
REPORT_PATH="$RUN_ROOT/report.md"

mkdir -p "$WWW_ROOT" "$DOWNLOADS_ROOT" "$CERT_ROOT" "$LOGS_ROOT"
printf "small http3 fixture" > "$WWW_ROOT/small.txt"
: > "$WWW_ROOT/empty.txt"
python - "$WWW_ROOT/large.bin" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_bytes(bytes((i % 251 for i in range(2 * 1024 * 1024))))
PY

write_result() {
  local target="$1"
  local scenario="$2"
  local status="$3"
  local detail="$4"
  local artifact="${5:-}"
  python - "$RESULTS_PATH" "$target" "$scenario" "$status" "$detail" "$artifact" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone
path = pathlib.Path(sys.argv[1])
row = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "target": sys.argv[2],
    "scenario": sys.argv[3],
    "status": sys.argv[4],
    "detail": sys.argv[5],
    "artifact": sys.argv[6],
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(row, separators=(",", ":")) + "\n")
PY
}

generate_cert() {
  if [[ -f "$CERT_ROOT/cert.pem" && -f "$CERT_ROOT/priv.key" ]]; then
    return
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    echo "OpenSSL is required to generate certificates." >&2
    exit 2
  fi
  cat > "$CERT_ROOT/openssl.cnf" <<'EOF'
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=incursa-http3-interop
[v3_req]
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
DNS.2=incursa-server
DNS.3=aioquic-server
DNS.4=quiche-server
DNS.5=ngtcp2-server
IP.1=127.0.0.1
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
    -keyout "$CERT_ROOT/priv.key" \
    -out "$CERT_ROOT/cert.pem" \
    -config "$CERT_ROOT/openssl.cnf"
}

scenario_path() {
  case "$1" in
    get-small) printf "/small.txt" ;;
    get-empty) printf "/empty.txt" ;;
    get-large) printf "/large.bin" ;;
    not-found) printf "/missing.txt" ;;
    *) printf "" ;;
  esac
}

expected_status() {
  if [[ "$1" == "not-found" ]]; then
    printf "404"
  else
    printf "200"
  fi
}

skip_reason() {
  local target="$1"
  local scenario="$2"
  case "$scenario" in
    get-small|get-empty|get-large|not-found) ;;
    *)
      printf "scenario requires a specialized peer behavior that is not wired in this first harness slice"
      return
      ;;
  esac

  case "$target" in
    incursa-client__incursa-server|curl__incursa-server) printf "" ;;
    *) printf "target is listed for matrix coverage but requires an external peer command image/server wiring" ;;
  esac
}

export HTTP3_INTEROP_WWW="$WWW_ROOT"
export HTTP3_INTEROP_DOWNLOADS="$DOWNLOADS_ROOT"
export HTTP3_INTEROP_CERTS="$CERT_ROOT"
export HTTP3_INTEROP_LOGS="$LOGS_ROOT"

if [[ "$PLAN_ONLY" -eq 0 ]]; then
  generate_cert
  up_args=(up --detach)
  if [[ "$SKIP_BUILD" -eq 0 ]]; then
    up_args+=(--build)
  fi
  up_args+=(incursa-server)
  docker compose --file "$COMPOSE_FILE" "${up_args[@]}"
  sleep 3
fi

cleanup() {
  if [[ "$PLAN_ONLY" -eq 0 && "$KEEP_SERVER" -eq 0 ]]; then
    docker compose --file "$COMPOSE_FILE" down --remove-orphans >/dev/null || true
  fi
}
trap cleanup EXIT

for target in "${TARGETS[@]}"; do
  for scenario in "${SCENARIOS[@]}"; do
    reason="$(skip_reason "$target" "$scenario")"
    if [[ -n "$reason" ]]; then
      write_result "$target" "$scenario" "skip" "$reason"
      continue
    fi

    path="$(scenario_path "$scenario")"
    status="$(expected_status "$scenario")"
    safe_name="${target}-${scenario}"
    artifact="$RUN_ROOT/${safe_name}.log"
    download_path="/downloads/${safe_name}.out"

    if [[ "$PLAN_ONLY" -eq 1 ]]; then
      write_result "$target" "$scenario" "skip" "plan-only" "$artifact"
      continue
    fi

    set +e
    if [[ "$target" == "incursa-client__incursa-server" ]]; then
      docker compose --file "$COMPOSE_FILE" run --rm --no-deps incursa-client \
        "https://incursa-server:4433${path}" "$download_path" --expect-status "$status" >"$artifact" 2>&1
      exit_code=$?
    elif [[ "$target" == "curl__incursa-server" && "$status" == "200" ]]; then
      docker compose --file "$COMPOSE_FILE" run --rm --no-deps curl \
        --http3-only --insecure --silent --show-error --fail \
        --output "$download_path" "https://incursa-server:4433${path}" >"$artifact" 2>&1
      exit_code=$?
    else
      docker compose --file "$COMPOSE_FILE" run --rm --no-deps curl \
        --http3-only --insecure --silent --show-error \
        --output "$download_path" --write-out "%{http_code}" \
        "https://incursa-server:4433${path}" >"$artifact" 2>&1
      exit_code=$?
    fi
    set -e

    if [[ "$exit_code" -eq 0 ]]; then
      write_result "$target" "$scenario" "pass" "exit code 0" "$artifact"
    else
      write_result "$target" "$scenario" "fail" "exit code $exit_code" "$artifact"
    fi
  done
done

python "$SCRIPT_DIR/parse-http3-results.py" "$RESULTS_PATH" --output "$REPORT_PATH"
echo "Results: $RESULTS_PATH"
echo "Report:  $REPORT_PATH"
