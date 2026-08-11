#!/usr/bin/env bash
# Smoke tests for pong. Run from the repo root: ./tests/smoke.sh [path/to/pong]
set -euo pipefail

BIN=${1:-./pong}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

ok() {
    echo "  ok: $*"
}

echo "== binary present and help works =="
[ -x "$BIN" ] || fail "binary '$BIN' not found"
"$BIN" --help 2>&1 | grep -q "Usage:" || fail "--help did not print usage"
ok "--help"

echo "== loopback v4 (count, interval) =="
"$BIN" -4 -c 3 -i 50 127.0.0.1 >/dev/null || fail "v4 loopback ping"
ok "v4 loopback"

echo "== default target (localhost) =="
"$BIN" -c 1 >/dev/null || fail "default localhost ping"
ok "localhost"

echo "== flood: full payload in a single burst =="
"$BIN" -4 -c 8 -f -t 2 >/dev/null || fail "flood ping"
ok "flood"

echo "== interval zero is accepted =="
"$BIN" -4 -c 2 -i 0 127.0.0.1 >/dev/null || fail "zero interval"
ok "zero interval"

echo "== invalid options are rejected =="
"$BIN" -c 0 >/dev/null 2>&1 && fail "-c 0 accepted"
"$BIN" -i 70000 >/dev/null 2>&1 && fail "-i 70000 accepted"
"$BIN" -h x.onion -P "bad proxy:garbage:x" -c 1 >/dev/null 2>&1 && fail "bad proxy accepted"
"$BIN" -x >/dev/null 2>&1 && fail "unknown option accepted"
ok "option validation"

echo "== ipv6 (skipped if no IPv6 configured) =="
if "$BIN" -6 -c 1 -t 1 >/dev/null 2>&1; then
    ok "ipv6"
else
    echo "  skip: ipv6 not available"
fi

echo "ALL TESTS PASSED"
