#!/usr/bin/env bash
# Start a local Nano engine (the prebuilt `nanobpm-gateway-rest-server` that
# c8ctl-plugin-nano ships per platform) on localhost:$PORT for the contract
# tests, and wait until its REST API answers.
#
#   start-nano-engine.sh <version> [port]
#
# The engine is local-only; the harness refuses any non-localhost URL.
set -euo pipefail

version="${1:?usage: start-nano-engine.sh <version> [port]}"
port="${2:-8080}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) plat=linux-x64 ;;
  Linux-aarch64) plat=linux-arm64 ;;
  Darwin-arm64) plat=darwin-arm64 ;;
  Darwin-x86_64) plat=darwin-x64 ;;
  *) echo "::error::no prebuilt nano engine for $(uname -s)-$(uname -m)"; exit 1 ;;
esac

dir="${RUNNER_TEMP:-/tmp}/nano-engine"
rm -rf "$dir" && mkdir -p "$dir/data"
npm pack "@nanobpm/c8ctl-plugin-nano-${plat}@${version}" --pack-destination "$dir" --silent
tar xzf "$dir"/nanobpm-c8ctl-plugin-nano-*.tgz -C "$dir"
bin="$dir/package/nanobpm-gateway-rest-server"
"$bin" --version

PORT="$port" NANOBPMN_CONSOLE=off NANOBPMN_METRICS=off NANOBPMN_DATA_DIR="$dir/data" \
  nohup "$bin" >"$dir/engine.log" 2>&1 &
echo "engine pid $!"

for _ in $(seq 60); do
  if curl -sf "http://localhost:${port}/v2/topology" >/dev/null; then
    echo "nano engine ${version} ready on :${port}"
    exit 0
  fi
  sleep 1
done
echo "::error::nano engine did not become ready"
cat "$dir/engine.log"
exit 1
