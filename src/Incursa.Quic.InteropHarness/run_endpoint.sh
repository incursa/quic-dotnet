#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

"$SCRIPT_DIR/setup.sh"

if [[ "${ROLE:-}" == "client" ]]; then
    echo "Waiting for simulator control port..."
    for attempt in $(seq 1 30); do
        if bash -c "exec 3<>/dev/tcp/sim/57832" 2>/dev/null; then
            break
        fi

        if [[ "$attempt" == "30" ]]; then
            echo "Timed out waiting for sim:57832." >&2
            exit 1
        fi

        sleep 1
    done
fi

exec dotnet "$SCRIPT_DIR/Incursa.Quic.InteropHarness.dll" "$@"
