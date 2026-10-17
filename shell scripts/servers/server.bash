brew install nmap

#!/usr/bin/env bash
# Authorized, low-impact web vulnerability triage. Scan only assets in scope.
set -Eeuo pipefail
IFS=$'\n\t'

usage() {
    echo "Usage: AUTHORIZED=1 $0 example.com [resolver-file]" >&2
    echo "Run only against domains you are explicitly authorized to test." >&2
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    usage
    exit 0
fi
if [[ $# -lt 1 ]]; then
    usage
    exit 2
fi
if [[ ${AUTHORIZED:-} != 1 ]]; then
    echo "Refusing to scan: set AUTHORIZED=1 after confirming written permission." >&2
    exit 2
fi

domain=${1,,}
domain=${domain%.}
if [[ ! $domain =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]; then
    echo "Invalid domain: $domain" >&2
    exit 2
fi

resolver_file=${2:-}
if [[ -n $resolver_file && ! -r $resolver_file ]]; then
    echo "Resolver file is not readable: $resolver_file" >&2
    exit 2
fi
for tool in subfinder assetfinder amass httpx nuclei; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool not found: $tool" >&2
        exit 127
    fi
done

out="$PWD/$domain"
mkdir -p "$out/sources" "$out/Recon/httpx" "$out/Recon/nuclei"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Collecting passive subdomain results for $domain..."
subfinder -silent -d "$domain" -o "$tmp/subfinder.txt"
assetfinder --subs-only "$domain" > "$tmp/assetfinder.txt"
amass enum -passive -d "$domain" -o "$tmp/amass.txt"

# Discard out-of-scope names before making HTTP requests.
cat "$tmp/subfinder.txt" "$tmp/assetfinder.txt" "$tmp/amass.txt" 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/\.$//' \
    | awk -v root="$domain" '$0 == root || (length($0) > length(root) && substr($0, length($0)-length(root), length(root)+1) == "." root)' \
    | sort -u > "$out/sources/all.txt"
printf '%s\n' "$domain" >> "$out/sources/all.txt"
sort -u -o "$out/sources/all.txt" "$out/sources/all.txt"

httpx_args=(-silent -l "$out/sources/all.txt" -threads 5 -rate-limit 5 -timeout 5 -retries 1 -o "$out/Recon/httpx/live.txt")
if [[ -n $resolver_file ]]; then
    httpx_args+=(-resolver "$resolver_file")
fi
httpx "${httpx_args[@]}"

if [[ ! -s "$out/Recon/httpx/live.txt" ]]; then
    echo "No live in-scope HTTP services found; no vulnerability scan performed." >&2
    exit 0
fi

echo "Running rate-limited checks for common exposures and misconfigurations..."
nuclei -silent -l "$out/Recon/httpx/live.txt" \
    -tags misconfig,exposure \
    -severity info,low,medium,high,critical \
    -rate-limit 5 -concurrency 5 -retries 1 \
    -jsonl-export "$out/Recon/nuclei/findings.jsonl" \
    -o "$out/Recon/nuclei/findings.txt"

echo "Finished. Results: $out/Recon/nuclei/findings.txt"
}
