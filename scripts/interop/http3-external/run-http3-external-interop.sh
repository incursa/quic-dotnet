#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
ARTIFACTS_ROOT="${ARTIFACTS_ROOT:-.artifacts/http3-external}"
PLAN_ONLY=0
SKIP_BUILD=0
KEEP_SERVER=0
PCAP_SOURCE="${PCAP_SOURCE:-}"
PYTHON_BIN="${PYTHON_BIN:-}"
SERVER_CONNECT_TO=""

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
    --pcap-source)
      PCAP_SOURCE="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python)"
  else
    echo "Python 3 is required for fixture generation and result parsing." >&2
    exit 2
  fi
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ROOT="$REPO_ROOT/$ARTIFACTS_ROOT/$RUN_ID"
WWW_ROOT="$RUN_ROOT/www"
DOWNLOADS_ROOT="$RUN_ROOT/downloads"
CERT_ROOT="$RUN_ROOT/certs"
LOGS_ROOT="$RUN_ROOT/logs"
SCENARIO_ROOT="$RUN_ROOT/scenarios"
PCAP_ROOT="$RUN_ROOT/pcaps"
RESULTS_PATH="$RUN_ROOT/results.jsonl"
REPORT_PATH="$RUN_ROOT/report.md"
PEER_TOOL_MANIFEST_PATH="$RUN_ROOT/peer-tool-manifest.json"

mkdir -p "$WWW_ROOT" "$DOWNLOADS_ROOT" "$CERT_ROOT" "$LOGS_ROOT" "$SCENARIO_ROOT" "$PCAP_ROOT"
printf "small http3 fixture" > "$WWW_ROOT/small.txt"
: > "$WWW_ROOT/empty.txt"
"$PYTHON_BIN" - "$WWW_ROOT/large.bin" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_bytes(bytes((i % 251 for i in range(64 * 1024))))
PY

write_result() {
  local target="$1"
  local scenario="$2"
  local status="$3"
  local detail="$4"
  local artifact="${5:-}"
  "$PYTHON_BIN" - "$RESULTS_PATH" "$target" "$scenario" "$status" "$detail" "$artifact" <<'PY'
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

write_summary() {
  local artifact_dir="$1"
  local target="$2"
  local scenario="$3"
  local status="$4"
  local detail="$5"
  local exit_code="$6"
  local command_line="$7"
  "$PYTHON_BIN" - "$artifact_dir/http3-summary.json" "$target" "$scenario" "$status" "$detail" "$exit_code" "$command_line" "$LOGS_ROOT" "$PCAP_ROOT" <<'PY'
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
    "exitCode": int(sys.argv[6]),
    "command": sys.argv[7],
    "artifacts": {
        "stdout": "stdout.log",
        "stderr": "stderr.log",
        "command": "command.txt",
        "qlog": f"{sys.argv[8]}/*/qlog",
        "sslKeyLog": f"{sys.argv[8]}/*/sslkeylog/keys.log",
        "pcaps": sys.argv[9],
    },
}
path.write_text(json.dumps(row, indent=2), encoding="utf-8")
PY
}

write_peer_tool_manifest() {
  HTTP3_MANIFEST_RUN_ID="$RUN_ID" \
  HTTP3_MANIFEST_PATH="$PEER_TOOL_MANIFEST_PATH" \
  HTTP3_MANIFEST_COMPOSE_FILE="$COMPOSE_FILE" \
  HTTP3_MANIFEST_PLAN_ONLY="$PLAN_ONLY" \
  HTTP3_MANIFEST_TARGETS="$(printf "%s\n" "${TARGETS[@]}")" \
  HTTP3_MANIFEST_SCENARIOS="$(printf "%s\n" "${SCENARIOS[@]}")" \
  "$PYTHON_BIN" <<'PY'
import json
import os
import pathlib
import subprocess
from datetime import datetime, timezone

def command_text(args):
    try:
        completed = subprocess.run(args, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()

def image_info(image):
    image_id = command_text(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    digests_raw = command_text(["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"])
    try:
        repo_digests = json.loads(digests_raw) if digests_raw and digests_raw != "null" else []
    except json.JSONDecodeError:
        repo_digests = []
    return {"image": image, "resolvedImageId": image_id, "repoDigests": repo_digests}

def tool(tool, kind, env_var, image, roles, scenarios, commands, limitations, package=None):
    return {
        "tool": tool,
        "type": kind,
        "environmentVariable": env_var,
        "package": package or {},
        "image": image_info(image),
        "roles": roles,
        "supportedScenarios": scenarios,
        "commandLineTemplates": commands,
        "knownLimitations": limitations,
    }

static_get = ["get-small", "get-empty", "get-large", "not-found"]
static_with_headers = ["get-small", "get-empty", "get-large", "not-found", "many-headers", "split-data"]
curl_image = os.environ.get("HTTP3_CURL_IMAGE") or "ghcr.io/macbre/curl-http3"
quiche_image = os.environ.get("HTTP3_QUICHE_IMAGE") or "cloudflare/quiche:latest"
ngtcp2_image = os.environ.get("HTTP3_NGTCP2_IMAGE") or "ghcr.io/ngtcp2/ngtcp2-interop:latest"
aioquic_image = "incursa-http3-external-interop-aioquic:latest"

manifest = {
    "schemaVersion": "http3-external-peer-tools-v1",
    "runId": os.environ["HTTP3_MANIFEST_RUN_ID"],
    "generatedUtc": datetime.now(timezone.utc).isoformat(),
    "planOnly": os.environ["HTTP3_MANIFEST_PLAN_ONLY"] == "1",
    "composeFile": os.environ["HTTP3_MANIFEST_COMPOSE_FILE"],
    "targets": [item for item in os.environ["HTTP3_MANIFEST_TARGETS"].splitlines() if item],
    "scenarios": [item for item in os.environ["HTTP3_MANIFEST_SCENARIOS"].splitlines() if item],
    "docker": {
        "version": command_text(["docker", "--version"]),
        "composeVersion": command_text(["docker", "compose", "version"]),
    },
    "acquisition": {
        "aioquic": tool(
            "aioquic",
            "repo-local Docker build",
            "AIOQUIC_VERSION",
            aioquic_image,
            ["client", "server"],
            static_with_headers,
            [
                "aioquic-http3-client <url> <download-path> --expect-status <status>",
                "aioquic-http3-server /www /certs/cert.pem /certs/priv.key 4433",
            ],
            ["Repo-local wrapper around aioquic 1.3.0."],
            {"name": "aioquic", "version": "1.3.0", "dockerfile": "scripts/interop/http3-external/docker/aioquic.Dockerfile"},
        ),
        "curl": tool(
            "curl",
            "Docker image",
            "HTTP3_CURL_IMAGE",
            curl_image,
            ["client"],
            static_with_headers,
            ["curl --http3-only --max-time 15 --insecure --silent --show-error <url>"],
            ["Requires a curl build with --http3-only support.", "Client-only in this harness."],
        ),
        "quiche": tool(
            "quiche",
            "Docker image",
            "HTTP3_QUICHE_IMAGE",
            quiche_image,
            ["client", "server"],
            static_get,
            [
                "quiche-client --http-version HTTP/3 --no-verify --connect-to <ip:port> --dump-responses <dir> <url>",
                "quiche-server --listen 0.0.0.0:4433 --cert /certs/cert.pem --key /certs/priv.key --root /www --http-version HTTP/3",
            ],
            ["The image does not expose a --version flag; pin by image ID/repo digest.", "Header-heavy and split-response behavior are not wired for quiche-server rows."],
        ),
        "ngtcp2": tool(
            "ngtcp2/nghttp3",
            "Docker image",
            "HTTP3_NGTCP2_IMAGE",
            ngtcp2_image,
            ["client", "server"],
            static_get,
            [
                "wsslclient --download=/downloads --exit-on-all-streams-close --timeout=15s --handshake-timeout=10s --no-http-dump --qlog-dir=/logs/qlog <host> 4433 <url>",
                "wsslserver --htdocs=/www --qlog-dir=/logs/qlog --no-http-dump --timeout=15s --handshake-timeout=10s 0.0.0.0 4433 /certs/priv.key /certs/cert.pem",
            ],
            ["The interop image default entrypoint is bypassed for server rows.", "The image does not expose a stable no-argument --version output; pin by image ID/repo digest.", "Header-heavy and split-response behavior are not wired for ngtcp2-server rows."],
        ),
    },
    "evidenceClass": "external-peer-characterization",
    "notes": [
        "Resolved image IDs and repo digests are present only after Docker has pulled or built the image locally.",
        "Skipped rows remain evidence of missing peer command or scenario wiring, not support proof.",
    ],
}
path = pathlib.Path(os.environ["HTTP3_MANIFEST_PATH"])
path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
PY
}

copy_pcaps() {
  if [[ -z "$PCAP_SOURCE" ]]; then
    return
  fi
  if [[ ! -d "$PCAP_SOURCE" ]]; then
    echo "Packet capture source '$PCAP_SOURCE' does not exist." >&2
    return
  fi
  find "$PCAP_SOURCE" -type f \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.pcap.gz' -o -name '*.pcapng.gz' \) -exec cp -f {} "$PCAP_ROOT/" \;
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
  openssl ecparam -name prime256v1 -genkey -noout \
    -out "$CERT_ROOT/priv.key"
  openssl req -x509 -new -key "$CERT_ROOT/priv.key" -days 7 \
    -out "$CERT_ROOT/cert.pem" \
    -config "$CERT_ROOT/openssl.cnf"
}

scenario_path() {
  case "$1" in
    get-small) printf "/small.txt" ;;
    get-empty) printf "/empty.txt" ;;
    get-large) printf "/large.bin" ;;
    multiple-concurrent-get) printf "/small.txt" ;;
    not-found) printf "/missing.txt" ;;
    many-headers) printf "/many-headers.txt" ;;
    split-data) printf "/split-data.bin" ;;
    request-cancellation) printf "/cancel.bin" ;;
    goaway) printf "/goaway.txt" ;;
    connection-close-in-flight) printf "/close-in-flight.bin" ;;
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

server_connect_to_address() {
  local container_id
  container_id="$(docker compose --file "$COMPOSE_FILE" ps -q incursa-server)"
  if [[ -z "$container_id" ]]; then
    echo "Could not resolve the running incursa-server container id." >&2
    return 1
  fi

  local server_ip
  server_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container_id")"
  if [[ -z "$server_ip" ]]; then
    echo "Could not resolve the incursa-server container IP address." >&2
    return 1
  fi

  printf '%s:%s' "$server_ip" "4433"
}

server_network_name() {
  local container_id
  container_id="$(docker compose --file "$COMPOSE_FILE" ps -q incursa-server)"
  if [[ -z "$container_id" ]]; then
    echo "Could not resolve the running incursa-server container id." >&2
    return 1
  fi

  local network_name
  network_name="$(docker inspect --format '{{range $networkName, $network := .NetworkSettings.Networks}}{{$networkName}}{{end}}' "$container_id")"
  if [[ -z "$network_name" ]]; then
    echo "Could not resolve the incursa-server Docker network name." >&2
    return 1
  fi

  printf '%s' "$network_name"
}

skip_reason() {
  local target="$1"
  local scenario="$2"
  case "$target" in
    incursa-client__incursa-server)
      case "$scenario" in
        get-small|get-empty|get-large|multiple-concurrent-get|not-found|many-headers|split-data|request-cancellation|goaway|connection-close-in-flight) printf "" ;;
        *) printf "scenario requires a specialized peer behavior that is not wired in this first harness slice" ;;
      esac
      ;;
    curl__incursa-server)
      case "$scenario" in
        get-small|get-empty|get-large|not-found|many-headers|split-data) printf "" ;;
        *) printf "scenario requires a specialized peer behavior that is not wired in this first harness slice" ;;
      esac
      ;;
    aioquic-client__incursa-server)
      case "$scenario" in
        get-small|get-empty|not-found|many-headers) printf "" ;;
        get-large|split-data) printf "aioquic 1.3.0 large-body peer incompatibility; these rows are documented skips until the peer library is upgraded or replaced" ;;
        *) printf "scenario requires a specialized peer behavior that is not wired in this first harness slice" ;;
      esac
      ;;
    quiche-client__incursa-server)
      case "$scenario" in
        get-small|get-empty|get-large|not-found|many-headers|split-data) printf "" ;;
        *) printf "scenario requires a specialized peer behavior that is not wired in this first harness slice" ;;
      esac
      ;;
    ngtcp2-client__incursa-server)
      case "$scenario" in
        get-small|get-empty|get-large|not-found|many-headers|split-data) printf "" ;;
        *) printf "scenario requires a specialized peer behavior that is not wired in this first harness slice" ;;
      esac
      ;;
    incursa-client__aioquic-server)
      case "$scenario" in
        get-small|get-empty|get-large|not-found|many-headers|split-data) printf "" ;;
        *) printf "scenario requires a specialized peer behavior that is not wired in this first harness slice" ;;
      esac
      ;;
    *) printf "target is listed for matrix coverage but requires an external peer command image/server wiring" ;;
  esac
}

export HTTP3_INTEROP_WWW="$WWW_ROOT"
export HTTP3_INTEROP_DOWNLOADS="$DOWNLOADS_ROOT"
export HTTP3_INTEROP_CERTS="$CERT_ROOT"
export HTTP3_INTEROP_LOGS="$LOGS_ROOT"

if [[ "$PLAN_ONLY" -eq 0 ]]; then
  generate_cert
  if [[ "$SKIP_BUILD" -eq 0 ]]; then
    docker compose --file "$COMPOSE_FILE" build incursa-server incursa-client aioquic
  fi
  up_args=(up --detach)
  up_args+=(incursa-server)
  if [[ " ${TARGETS[*]} " == *" incursa-client__aioquic-server "* ]]; then
    up_args+=(aioquic-server)
  fi
  docker compose --file "$COMPOSE_FILE" "${up_args[@]}"
  sleep 3
  SERVER_CONNECT_TO="$(server_connect_to_address)"
  SERVER_NETWORK_NAME="$(server_network_name)"
fi

cleanup() {
  if [[ "$PLAN_ONLY" -eq 0 && "$KEEP_SERVER" -eq 0 ]]; then
    docker compose --file "$COMPOSE_FILE" logs --no-color incursa-server >"$RUN_ROOT/server.stdout.log" 2>"$RUN_ROOT/server.stderr.log" || true
    if [[ " ${TARGETS[*]} " == *" incursa-client__aioquic-server "* ]]; then
      docker compose --file "$COMPOSE_FILE" logs --no-color aioquic-server >"$RUN_ROOT/aioquic-server.stdout.log" 2>"$RUN_ROOT/aioquic-server.stderr.log" || true
      docker compose --file "$COMPOSE_FILE" --profile peers stop aioquic-server >/dev/null || true
      docker compose --file "$COMPOSE_FILE" --profile peers rm --force aioquic-server >/dev/null || true
    fi
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
    artifact_dir="$SCENARIO_ROOT/$safe_name"
    mkdir -p "$artifact_dir"
    stdout_path="$artifact_dir/stdout.log"
    stderr_path="$artifact_dir/stderr.log"
    command_path="$artifact_dir/command.txt"
    download_path="/downloads/${safe_name}.out"

    if [[ "$PLAN_ONLY" -eq 1 ]]; then
      printf "plan-only\n" > "$command_path"
      : > "$stdout_path"
      : > "$stderr_path"
      write_summary "$artifact_dir" "$target" "$scenario" "skip" "plan-only" 0 "plan-only"
      write_result "$target" "$scenario" "skip" "plan-only" "$artifact_dir"
      continue
    fi

    set +e
    if [[ "$target" == "incursa-client__incursa-server" && "$scenario" == "multiple-concurrent-get" ]]; then
      client_count=4
      command_lines=()
      pids=()
      for index in $(seq 0 $((client_count - 1))); do
        client_stdout="$artifact_dir/stdout.$index.log"
        client_stderr="$artifact_dir/stderr.$index.log"
        concurrent_download_path="/downloads/${safe_name}-${index}.out"
        command_line="docker compose --file \"$COMPOSE_FILE\" run --rm --no-deps incursa-client https://incursa-server:4433/small.txt $concurrent_download_path --expect-status 200"
        command_lines+=("$command_line")
        docker compose --file "$COMPOSE_FILE" run --rm --no-deps incursa-client \
          "https://incursa-server:4433/small.txt" "$concurrent_download_path" --expect-status 200 >"$client_stdout" 2>"$client_stderr" &
        pids+=("$!")
      done
      printf "%s\n" "${command_lines[@]}" > "$command_path"
      exit_codes=()
      exit_code=0
      for pid in "${pids[@]}"; do
        wait "$pid"
        code=$?
        exit_codes+=("$code")
        if [[ "$code" -ne 0 && "$exit_code" -eq 0 ]]; then
          exit_code="$code"
        fi
      done
      for index in $(seq 0 $((client_count - 1))); do
        {
          printf "=== client %s stdout ===\n" "$index"
          cat "$artifact_dir/stdout.$index.log" 2>/dev/null || true
        } >>"$stdout_path"
        {
          printf "=== client %s stderr ===\n" "$index"
          cat "$artifact_dir/stderr.$index.log" 2>/dev/null || true
        } >>"$stderr_path"
      done
      command_line="$(printf "%s; " "${command_lines[@]}")"
    elif [[ "$target" == "incursa-client__incursa-server" ]]; then
      command_line="docker compose --file \"$COMPOSE_FILE\" run --rm --no-deps incursa-client https://incursa-server:4433${path} $download_path --expect-status $status"
      printf "%s\n" "$command_line" > "$command_path"
      extra_args=()
      if [[ "$scenario" == "many-headers" ]]; then
        extra_args+=(--expect-header-count-at-least 66)
      fi
      if [[ "$scenario" == "request-cancellation" ]]; then
        extra_args+=(--cancel-after-ms 150)
      fi
      docker compose --file "$COMPOSE_FILE" run --rm --no-deps incursa-client \
        "https://incursa-server:4433${path}" "$download_path" --expect-status "$status" "${extra_args[@]}" >"$stdout_path" 2>"$stderr_path"
      exit_code=$?
    elif [[ "$target" == "curl__incursa-server" && "$status" == "200" ]]; then
      command_line="docker compose --file \"$COMPOSE_FILE\" run --rm --no-deps curl --http3-only --max-time 15 --insecure --silent --show-error --fail --output $download_path https://incursa-server:4433${path}"
      printf "%s\n" "$command_line" > "$command_path"
      docker compose --file "$COMPOSE_FILE" run --rm --no-deps curl \
        --http3-only --max-time 15 --insecure --silent --show-error --fail \
        --output "$download_path" "https://incursa-server:4433${path}" >"$stdout_path" 2>"$stderr_path"
      exit_code=$?
    elif [[ "$target" == "curl__incursa-server" ]]; then
      command_line="docker compose --file \"$COMPOSE_FILE\" run --rm --no-deps curl --http3-only --max-time 15 --insecure --silent --show-error --output $download_path --write-out %{http_code} https://incursa-server:4433${path}"
      printf "%s\n" "$command_line" > "$command_path"
      docker compose --file "$COMPOSE_FILE" run --rm --no-deps curl \
        --http3-only --max-time 15 --insecure --silent --show-error \
        --output "$download_path" --write-out "%{http_code}" \
        "https://incursa-server:4433${path}" >"$stdout_path" 2>"$stderr_path"
      exit_code=$?
    elif [[ "$target" == "aioquic-client__incursa-server" ]]; then
      command_line="docker compose --file \"$COMPOSE_FILE\" run --rm --no-deps aioquic /usr/local/bin/aioquic-http3-client https://incursa-server:4433${path} $download_path --expect-status $status"
      printf "%s\n" "$command_line" > "$command_path"
      extra_args=()
      if [[ "$scenario" == "many-headers" ]]; then
        extra_args+=(--expect-header-count-at-least 66)
      fi
      docker compose --file "$COMPOSE_FILE" run --rm --no-deps aioquic \
        /usr/local/bin/aioquic-http3-client \
        "https://incursa-server:4433${path}" "$download_path" --expect-status "$status" "${extra_args[@]}" >"$stdout_path" 2>"$stderr_path"
      exit_code=$?
    elif [[ "$target" == "quiche-client__incursa-server" ]]; then
      quiche_container_name="incursa-http3-external-interop-quiche-$(cat /proc/sys/kernel/random/uuid | tr -d '-')"
      quiche_dump_directory="/downloads/${safe_name}"
      quiche_command="mkdir -p $quiche_dump_directory /logs/qlog /logs/sslkeylog && quiche-client --http-version HTTP/3 --no-verify --connect-to $SERVER_CONNECT_TO --dump-responses $quiche_dump_directory --dump-json --max-json-payload 0 https://incursa-server:4433${path}"
      command_line="docker run --name $quiche_container_name --network $SERVER_NETWORK_NAME -e QLOGDIR=/logs/qlog -e SSLKEYLOGFILE=/logs/sslkeylog/keys.log --entrypoint /bin/sh cloudflare/quiche:latest -lc \"$quiche_command\""
      printf "%s\n" "$command_line" > "$command_path"
      docker run \
        --name "$quiche_container_name" \
        --network "$SERVER_NETWORK_NAME" \
        -e QLOGDIR=/logs/qlog \
        -e SSLKEYLOGFILE=/logs/sslkeylog/keys.log \
        --entrypoint /bin/sh \
        cloudflare/quiche:latest \
        -lc "$quiche_command" >"$stdout_path" 2>"$stderr_path"
      exit_code=$?
      quiche_download_root="$artifact_dir/quiche-downloads"
      quiche_log_root="$LOGS_ROOT/quiche"
      mkdir -p "$quiche_download_root" "$quiche_log_root"
      if docker cp "${quiche_container_name}:/downloads/${safe_name}" "$quiche_download_root" >/dev/null 2>&1; then
        copied_file="$(find "$quiche_download_root" -type f | head -n 1 || true)"
        if [[ -n "$copied_file" ]]; then
          cp "$copied_file" "$download_path"
        fi
      fi
      docker cp "${quiche_container_name}:/logs/qlog" "$quiche_log_root" >/dev/null 2>&1 || true
      docker cp "${quiche_container_name}:/logs/sslkeylog" "$quiche_log_root" >/dev/null 2>&1 || true
      docker rm -f "$quiche_container_name" >/dev/null 2>&1 || true
    elif [[ "$target" == "ngtcp2-client__incursa-server" ]]; then
      ngtcp2_container_name="incursa-http3-external-interop-ngtcp2-$(cat /proc/sys/kernel/random/uuid | tr -d '-')"
      ngtcp2_image="${HTTP3_NGTCP2_IMAGE:-ghcr.io/ngtcp2/ngtcp2-interop:latest}"
      ngtcp2_log_root="$LOGS_ROOT/ngtcp2"
      mkdir -p "$ngtcp2_log_root"
      ngtcp2_command="mkdir -p /logs/qlog /logs/sslkeylog && wsslclient --download=/downloads --exit-on-all-streams-close --timeout=15s --handshake-timeout=10s --no-http-dump --qlog-dir=/logs/qlog incursa-server 4433 https://incursa-server:4433${path}"
      command_line="docker run --rm --name $ngtcp2_container_name --network $SERVER_NETWORK_NAME -v \"$WWW_ROOT:/www:ro\" -v \"$DOWNLOADS_ROOT:/downloads\" -v \"$CERT_ROOT:/certs:ro\" -v \"$ngtcp2_log_root:/logs\" -e QLOGDIR=/logs/qlog -e SSLKEYLOGFILE=/logs/sslkeylog/keys.log --entrypoint /bin/sh $ngtcp2_image -lc \"$ngtcp2_command\""
      printf "%s\n" "$command_line" > "$command_path"
      docker run \
        --rm \
        --name "$ngtcp2_container_name" \
        --network "$SERVER_NETWORK_NAME" \
        -v "$WWW_ROOT:/www:ro" \
        -v "$DOWNLOADS_ROOT:/downloads" \
        -v "$CERT_ROOT:/certs:ro" \
        -v "$ngtcp2_log_root:/logs" \
        -e QLOGDIR=/logs/qlog \
        -e SSLKEYLOGFILE=/logs/sslkeylog/keys.log \
        --entrypoint /bin/sh \
        "$ngtcp2_image" \
        -lc "$ngtcp2_command" >"$stdout_path" 2>"$stderr_path"
      exit_code=$?
    elif [[ "$target" == "incursa-client__aioquic-server" ]]; then
      command_line="docker compose --file \"$COMPOSE_FILE\" run --rm --no-deps incursa-client https://aioquic-server:4433${path} $download_path --expect-status $status"
      printf "%s\n" "$command_line" > "$command_path"
      compose_run_args=(run --rm --no-deps)
      if [[ "$scenario" == "many-headers" ]]; then
        extra_args=(--expect-header-count-at-least 66)
      else
        extra_args=()
      fi
      if [[ -n "${AIOQUIC_HTTP3_DEBUG:-}" ]]; then
        compose_run_args+=(-e "AIOQUIC_HTTP3_DEBUG=${AIOQUIC_HTTP3_DEBUG}")
      fi
      docker compose --file "$COMPOSE_FILE" "${compose_run_args[@]}" incursa-client \
        "https://aioquic-server:4433${path}" "$download_path" --expect-status "$status" "${extra_args[@]}" >"$stdout_path" 2>"$stderr_path"
      exit_code=$?
    fi
    set -e

    if grep -Eqi -- "ERR_HANDSHAKE_TIMEOUT|handshake timed out|handshake timeout" "$stderr_path"; then
      write_summary "$artifact_dir" "$target" "$scenario" "fail" "handshake timeout" "$exit_code" "$command_line"
      write_result "$target" "$scenario" "fail" "handshake timeout" "$artifact_dir"
    elif [[ "$exit_code" -eq 0 ]]; then
      write_summary "$artifact_dir" "$target" "$scenario" "pass" "exit code 0" "$exit_code" "$command_line"
      write_result "$target" "$scenario" "pass" "exit code 0" "$artifact_dir"
    elif [[ "$target" == "curl__incursa-server" ]] && grep -Eqi -- "option .*--http3|--http3-only.*unknown|unsupported protocol|the installed libcurl version doesn't support this" "$stderr_path"; then
      detail="curl image does not support HTTP/3; set HTTP3_CURL_IMAGE to a curl build with --http3-only support"
      write_summary "$artifact_dir" "$target" "$scenario" "skip" "$detail" "$exit_code" "$command_line"
      write_result "$target" "$scenario" "skip" "$detail" "$artifact_dir"
    else
      write_summary "$artifact_dir" "$target" "$scenario" "fail" "exit code $exit_code" "$exit_code" "$command_line"
      write_result "$target" "$scenario" "fail" "exit code $exit_code" "$artifact_dir"
    fi
  done
done

copy_pcaps
write_peer_tool_manifest
"$PYTHON_BIN" "$SCRIPT_DIR/parse-http3-results.py" "$RESULTS_PATH" --output "$REPORT_PATH"
echo "Results: $RESULTS_PATH"
echo "Report:  $REPORT_PATH"
echo "Tools:   $PEER_TOOL_MANIFEST_PATH"
