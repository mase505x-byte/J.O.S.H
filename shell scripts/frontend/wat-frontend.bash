#!/usr/bin/env bash
set -euo pipefail

# Exact hostnames may be listed in the project root's allowed_hosts.txt; the
# JOSH_ALLOWED_HOSTS environment variable can also add comma-separated entries.
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required." >&2; exit 1; }
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
echo "J.O.S.H. security workspace: http://127.0.0.1:${JOSH_PORT:-8000} (Ctrl+C to stop)"
python3 "$script_dir/../../sources/jam.py"
