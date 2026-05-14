#!/usr/bin/env bash
#
# audit-fp.sh — verify an aimap fingerprint against live Shodan-sourced
# candidates. Codifies the iter 10-13 audit pattern from the 2026-05-13
# bulletproofing session.
#
# Pattern: given a fingerprint name (and optionally a Shodan dork
# override), find up to N live candidate hosts, run the installed aimap
# binary against each, and report whether the FP fires.
#
# Outputs verdict per candidate: OK / MISS / TIMEOUT / DEAD.
# Exit status 0 if at least one OK, 1 if all candidates failed.
#
# Usage:
#   scripts/audit-fp.sh <FP_NAME> [--dork '<shodan-dork>'] [--limit N] [--scan-all]
#
# Examples:
#   scripts/audit-fp.sh MLflow
#   scripts/audit-fp.sh "Open WebUI" --limit 5 --scan-all
#   scripts/audit-fp.sh "Apache Pinot Controller" --dork 'http.html:"pinot-controller"'
#
# Flags:
#   --dork     Override the Shodan dork (default: 'http.title:"<FP_NAME>"')
#   --limit    Number of candidate hosts to probe (default: 3)
#   --scan-all Pass -scan-all-fingerprints to aimap. Use when candidates
#              are on non-canonical ports the FP doesn't list in
#              DefaultPorts. Slower but catches "wrong port" deployments.
#
# Requirements:
#   - aimap on $PATH (the version under test)
#   - shodan CLI initialized (`shodan init <key>`)
#   - python3 with the shodan package
#   - jq for JSON parsing
#
# The script writes per-candidate JSON reports under
#   /tmp/aimap-audit-<timestamp>/<plat>-<ip>-<port>.json
# so you can re-inspect them after the run.

set -euo pipefail

FP_NAME="${1:-}"
if [[ -z "$FP_NAME" ]]; then
  echo "usage: $0 <FP_NAME> [--dork '<dork>'] [--limit N]" >&2
  exit 2
fi
shift

DORK=""
LIMIT=3
SCAN_ALL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dork)  DORK="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    --scan-all) SCAN_ALL=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Default dork: search Shodan for the FP name appearing in HTML title.
# Crude but works for FPs with a distinctive title (most user-facing ones).
if [[ -z "$DORK" ]]; then
  DORK='http.title:"'"$FP_NAME"'"'
fi

# Output dir, dated
TS=$(date +%Y%m%d-%H%M%S)
OUTDIR="/tmp/aimap-audit-${TS}"
mkdir -p "$OUTDIR"
echo "[audit-fp] FP:      $FP_NAME"
echo "[audit-fp] dork:    $DORK"
echo "[audit-fp] limit:   $LIMIT candidates"
echo "[audit-fp] reports: $OUTDIR/"
echo

# Pull candidates via Shodan. Pass the dork via env var to dodge
# shell-quoting tangles inside the python heredoc.
CANDIDATES_JSON="$OUTDIR/candidates.json"
AIMAP_AUDIT_DORK="$DORK" AIMAP_AUDIT_LIMIT="$LIMIT" python3 <<'PY' > "$CANDIDATES_JSON"
import os, json, shodan
dork = os.environ['AIMAP_AUDIT_DORK']
limit = int(os.environ['AIMAP_AUDIT_LIMIT'])
api = shodan.Shodan(open(os.path.expanduser('~/.config/shodan/api_key')).read().strip())
try:
    r = api.search(dork, limit=limit)
    hits = []
    for m in r.get('matches', []):
        hits.append({
            'ip':    m.get('ip_str'),
            'port':  m.get('port'),
            'title': (m.get('http') or {}).get('title'),
        })
    print(json.dumps({'total': r.get('total', 0), 'hits': hits}, indent=2))
except shodan.APIError as e:
    print(json.dumps({'error': str(e)}))
PY

TOTAL=$(jq -r '.total // 0' "$CANDIDATES_JSON")
ERROR=$(jq -r '.error // empty' "$CANDIDATES_JSON")
if [[ -n "$ERROR" ]]; then
  echo "[audit-fp] shodan error: $ERROR" >&2
  exit 1
fi
HIT_COUNT=$(jq -r '.hits | length' "$CANDIDATES_JSON")
echo "[audit-fp] Shodan: $TOTAL total hits, probing $HIT_COUNT candidates"
echo

if [[ "$HIT_COUNT" -eq 0 ]]; then
  echo "[audit-fp] no candidates found for dork: $DORK" >&2
  echo "[audit-fp] try a different dork; the FP may exist for completeness only." >&2
  exit 1
fi

# Probe each candidate
PASS=0
TOTAL_PROBES=0
printf "  %-8s %-22s %-6s   %s\n" "STATUS" "HOST" "PORT" "DETAIL"
echo "  $(printf '%0.s-' {1..78})"

while IFS=$'\t' read -r ip port title; do
  TOTAL_PROBES=$((TOTAL_PROBES + 1))
  slug=$(echo "${FP_NAME}-${ip}-${port}" | tr ' /' '__')
  REPORT="$OUTDIR/${slug}.json"
  AIMAP_ARGS=(-target "$ip" -ports "$port" -threads 8 -timeout 5s -o "$REPORT")
  # Scan-all probes ~73 FPs (~150 HTTP requests per port). Use a much
  # longer subprocess timeout when -scan-all is enabled.
  PROBE_TIMEOUT=90
  if [[ "$SCAN_ALL" -eq 1 ]]; then
    AIMAP_ARGS+=(-scan-all-fingerprints)
    PROBE_TIMEOUT=300
  fi
  if timeout "$PROBE_TIMEOUT" aimap "${AIMAP_ARGS[@]}" >/dev/null 2>&1; then
    SERVICES=$(jq -r '.services[]?.service // empty' "$REPORT" 2>/dev/null | sort -u | paste -sd ',' -)
    if [[ -n "$SERVICES" ]]; then
      if [[ "$SERVICES" == *"$FP_NAME"* ]]; then
        printf "  \033[92m%-8s\033[0m %-22s %-6s   matched as: %s\n" "OK" "$ip" "$port" "$SERVICES"
        PASS=$((PASS + 1))
      else
        printf "  \033[93m%-8s\033[0m %-22s %-6s   matched as OTHER: %s (expected: %s)\n" "OTHER" "$ip" "$port" "$SERVICES" "$FP_NAME"
      fi
    else
      OPEN=$(jq -r '.open_ports | length' "$REPORT" 2>/dev/null)
      if [[ "$OPEN" -gt 0 ]]; then
        printf "  \033[91m%-8s\033[0m %-22s %-6s   port open, FP did NOT fire\n" "MISS" "$ip" "$port"
      else
        printf "  \033[2m%-8s\033[0m %-22s %-6s   port closed/unreachable\n" "DEAD" "$ip" "$port"
      fi
    fi
  else
    printf "  \033[2m%-8s\033[0m %-22s %-6s   aimap >90s\n" "TIMEOUT" "$ip" "$port"
  fi
done < <(jq -r '.hits[] | [.ip, .port, .title // ""] | @tsv' "$CANDIDATES_JSON")

echo
echo "[audit-fp] $PASS / $TOTAL_PROBES candidates classified as $FP_NAME"
echo "[audit-fp] per-candidate JSON in: $OUTDIR/"

if [[ "$PASS" -eq 0 ]]; then
  exit 1
fi
