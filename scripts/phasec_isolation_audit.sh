#!/usr/bin/env bash
# PHASE C L1 — ISOLATION AUDIT (owner order 2026-11-11: "is the benchmark
# on 8 weak apps or Juice Shop alone? Juice Shop as dev set, not isolated set")
# Method: fixed-string grep over the ENTIRE tracked tree of origin/main
# (not just worklog/STATE) — the auditable committed record.
# Output: per-app file-count + match-count, classified into
#   CONTAMINATED (scanned/tuned), MENTIONED-NOT-SCANNED, CLEAN (zero mentions).
set -uo pipefail
cd /home/z/my-project/burhan

audit () {  # $1 = fixed string, $2 = label
  local files matches
  files=$(git grep -i -l -F "$1" origin/main -- . 2>/dev/null | wc -l | tr -d ' ')
  matches=$(git grep -i -c -F "$1" origin/main -- . 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}')
  printf "%-16s files:%-4s matches:%s\n" "$2" "$files" "$matches"
}

echo "=== CONTAMINATION AUDIT — full tracked tree of origin/main ==="
echo "--- scanned/tuned (expect hits) ---"
audit "juice"          "JuiceShop"
audit "webgoat"        "WebGoat"
audit "benchmarkjava"  "BenchmarkJava"
audit "testfire"       "Altoro/testfire"
audit "altoro"         "Altoro"
audit "vulnweb"        "vulnweb x3"
audit "crapi"          "crAPI"
audit "dvwa"           "DVWA"
audit "wrongsecrets"   "WrongSecrets"
echo "--- mentioned, never scanned (r19 env infeasibility) ---"
audit "mutillidae"     "Mutillidae"
audit "nodegoat"       "NodeGoat"
audit "dvga"           "DVGA"
audit "dvws"           "DVWS"
echo "--- clean candidates (expect zero) ---"
audit "bwapp"          "bWAPP"
audit "railsgoat"      "RailGoat"
audit "shepherd"       "SecShepherd"
audit "vampi"          "VAMPI"
audit "dvja"           "DVJA"
audit "hackazon"       "Hackazon"
audit "igoat"          "iGoat"
echo "--- context only ---"
audit "maxtest"        "maxtest(campaign)"
echo
echo "=== sanity: where do clean-candidate hits live (if any) ==="
for app in bwapp railsgoat shepherd vampi dvja hackazon igoat; do
  hits=$(git grep -i -l -F "$app" origin/main -- . 2>/dev/null | head -3)
  [ -n "$hits" ] && echo "$app: $hits"
done
echo "(empty = zero mentions anywhere in the tracked tree)"
