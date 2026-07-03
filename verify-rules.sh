#!/bin/sh
# verify-rules.sh - fetch claude-running.txt, verify its SHA-256 against a
# locally pinned allowlist, and install it ONLY on a match. Refuse otherwise.
#
# Run at setup and any time you want to refresh the local rules. Sessions read
# the installed local copy; this gate is the only thing that updates it, so a
# hijacked remote can never silently replace your rules - it just fails here.
#
# Override any of these via env:
RULES_URL="${RULES_URL:-https://raw.githubusercontent.com/amrthabit/claude-rules/main/claude-running.txt}"
PIN_FILE="${PIN_FILE:-$HOME/.claude-rules/trusted-hashes.txt}"
OUT_FILE="${OUT_FILE:-$HOME/.claude-rules/claude-running.txt}"

set -eu

sha() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi | cut -d' ' -f1
}

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

curl -fsSL "$RULES_URL" -o "$tmp" || {
  echo "FAIL: could not fetch $RULES_URL" >&2
  exit 1
}

got="$(sha "$tmp")"

if [ ! -f "$PIN_FILE" ]; then
  echo "FAIL: no local trust pin at $PIN_FILE" >&2
  echo "fetched hash: $got" >&2
  echo "To trust this (first install / TOFU), confirm the hash out of band," >&2
  echo "then add it to the pin file:  echo '$got  running' >> $PIN_FILE" >&2
  exit 1
fi

if grep -qi "^${got}" "$PIN_FILE"; then
  mkdir -p "$(dirname "$OUT_FILE")"
  cp "$tmp" "$OUT_FILE"
  echo "OK: verified ${got}"
  echo "installed -> $OUT_FILE"
else
  echo "FAIL: fetched hash is NOT in the trusted pin list." >&2
  echo "fetched: ${got}" >&2
  echo "trusted:" >&2
  grep -vE '^[[:space:]]*(#|$)' "$PIN_FILE" >&2
  echo "REFUSING to install. Do NOT load these rules until you re-pin from a" >&2
  echo "hash you confirmed out of band." >&2
  exit 1
fi
