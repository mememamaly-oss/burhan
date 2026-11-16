#!/usr/bin/env bash
set -euo pipefail

NETWORK=burhan-dev
CRAPI_COMMIT=700f03d12a392d9e408260b4beae72ed02a4a1a4
TEMPLATE_DIR="${NUCLEI_TEMPLATE_DIR:-$PWD/.ci/nuclei-templates}"
TEMPLATE_COUNT_FILE="${NUCLEI_TEMPLATE_COUNT_FILE:-$PWD/.ci/nuclei-template-count}"
JUICE='docker.io/bkimminich/juice-shop@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27'
WEBGOAT='docker.io/webgoat/webgoat@sha256:2775102b8186df1656f8a69cfb7a6bf6c77b43a25fa0accd6d44e6ae04c8d3b7'
DVWA='docker.io/vulnerables/web-dvwa@sha256:14c929ec1a99edb77326201f7f0fb431d1b3dd099c09ddeaf46312ab0ff53cfe'
ZAP='docker.io/zaproxy/zap-stable@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af'
NUCLEI='docker.io/projectdiscovery/nuclei@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97'

cleanup() {
  docker compose -p crapi -f /tmp/crapi-compose.yml down -v --remove-orphans 2>/dev/null || true
  docker rm -f dev-juice dev-webgoat dev-dvwa 2>/dev/null || true
  docker network rm "$NETWORK" 2>/dev/null || true
}
trap cleanup EXIT

test -d "$TEMPLATE_DIR" || { echo "Nuclei template directory missing: $TEMPLATE_DIR" >&2; exit 1; }
test -s "$TEMPLATE_COUNT_FILE" || { echo "Nuclei template count file missing" >&2; exit 1; }
TEMPLATE_COUNT="$(cat "$TEMPLATE_COUNT_FILE")"
case "$TEMPLATE_COUNT" in ''|*[!0-9]*) echo "invalid template count: $TEMPLATE_COUNT" >&2; exit 1;; esac
(( TEMPLATE_COUNT > 0 )) || { echo "zero Nuclei templates loaded" >&2; exit 1; }
printf 'nuclei_templates_version=v10.5.0\n'
printf 'nuclei_templates_commit=f8b8b8dcd70d93826c3767e1829ef8243af9f03b\n'
printf 'nuclei_templates_tar_sha256=80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41\n'
printf 'nuclei_templates_loaded=%s\n' "$TEMPLATE_COUNT"

docker pull "$ZAP"
docker pull "$NUCLEI"
docker run --rm --network host -v "$TEMPLATE_DIR:/templates:ro" "$NUCLEI" -duc -t /templates -tl > /tmp/nuclei-template-list.txt 2>/tmp/nuclei-template-list.log
RUNTIME_TEMPLATE_COUNT="$(wc -l < /tmp/nuclei-template-list.txt | tr -d ' ')"
printf 'nuclei_runtime_templates_listed=%s\n' "$RUNTIME_TEMPLATE_COUNT"
(( RUNTIME_TEMPLATE_COUNT > 0 )) || { cat /tmp/nuclei-template-list.log >&2; exit 1; }

docker network create "$NETWORK"
docker run -d --name dev-juice --network "$NETWORK" --network-alias juice-shop -p 127.0.0.1:3000:3000 "$JUICE"
docker run -d --name dev-webgoat --network "$NETWORK" --network-alias webgoat -p 127.0.0.1:8080:8080 "$WEBGOAT"
docker run -d --name dev-dvwa --network "$NETWORK" --network-alias dvwa -p 127.0.0.1:8081:80 "$DVWA"

curl -fsSL "https://raw.githubusercontent.com/OWASP/crAPI/${CRAPI_COMMIT}/deploy/docker/docker-compose.yml" -o /tmp/crapi-compose.yml
python3 - <<'PY'
from pathlib import Path
p = Path('/tmp/crapi-compose.yml')
s = p.read_text()
replacements = {
    'crapi/crapi-identity:${VERSION:-latest}': 'crapi/crapi-identity@sha256:5d1db5b3ba8e02bc68711ec6fc4e35ed7cd8b87e63785ece9e7ff5b5e36c5260',
    'crapi/crapi-community:${VERSION:-latest}': 'crapi/crapi-community@sha256:8ba0c7eda86ae065a673f1fa554d0109a24f25c5a8d65097ae024e5ee715c54e',
    'crapi/crapi-workshop:${VERSION:-latest}': 'crapi/crapi-workshop@sha256:d4d2d94d35a31e211b04d5a771881f5ae13e358e8fa0804463ae3bace05dd815',
    'crapi/crapi-chatbot:${VERSION:-latest}': 'crapi/crapi-chatbot@sha256:36d274d54182a8baddba7ede17282035bb43ab9cb9cf87927e1fe7109901e0aa',
    'crapi/crapi-web:${VERSION:-latest}': 'crapi/crapi-web@sha256:b27d246c646bd33898e7d1d2095b6e7576c0993a7b81a73aa7386929493d7151',
    'crapi/gateway-service:${VERSION:-latest}': 'crapi/gateway-service@sha256:97dade9daf0e758547b1686e2d3303c8c9b79838167f728a9211f0ee1f4622b0',
    'crapi/mailhog:${VERSION:-latest}': 'crapi/mailhog@sha256:015c23f79d40c9dc1800cd0a458503b89aeda3b585a12c37d53829d6c7d61fdd',
    "'postgres:14'": "'postgres@sha256:c0e9c0e9bac7e4c1834b698217a03ee5c708de30d313c84a506972de0e24b059'",
    "'mongo:4.4'": "'mongo@sha256:4be76f674fc4b27859816811b8baa3c51830eb1dbf4ca81a51e26b79edd662ef'",
    "'chromadb/chroma:latest'": "'chromadb/chroma@sha256:1e0b73a187a28757c572acba508c46f48c9e8b0acaf5c20e6d95cdedce1acdf6'",
}
for old, new in replacements.items():
    if old not in s:
        raise SystemExit(f'missing expected crAPI image reference: {old}')
    s = s.replace(old, new)
s += '\nnetworks:\n  default:\n    name: burhan-dev\n    external: true\n'
p.write_text(s)
PY
docker compose -p crapi -f /tmp/crapi-compose.yml up -d

wait_http() {
  local name="$1" url="$2" deadline=$((SECONDS + 300))
  while (( SECONDS < deadline )); do
    local code
    code="$(curl -ksS -o /dev/null -w '%{http_code}' --max-time 5 "$url" || true)"
    case "$code" in 2??|3??) echo "$name ready ($code)"; return 0;; esac
    sleep 5
  done
  echo "target did not become ready: $name $url" >&2
  return 1
}
wait_http juice-shop http://127.0.0.1:3000/
wait_http webgoat http://127.0.0.1:8080/WebGoat/
wait_http dvwa http://127.0.0.1:8081/
wait_http crapi http://127.0.0.1:8888/

mkdir -p artifacts
cat > artifacts/nuclei-run-metadata.json <<EOF
{
  "engine_image": "$NUCLEI",
  "templates_version": "v10.5.0",
  "templates_commit": "f8b8b8dcd70d93826c3767e1829ef8243af9f03b",
  "templates_tar_sha256": "80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41",
  "templates_loaded": $TEMPLATE_COUNT,
  "runtime_templates_listed": $RUNTIME_TEMPLATE_COUNT,
  "scan_mode": "Nuclei HTTP templates; no ZAP active scan"
}
EOF

declare -A TARGETS=(
  [juice-shop]=http://juice-shop:3000/
  [crapi]=http://crapi-web:80/
  [webgoat]=http://webgoat:8080/WebGoat/
  [dvwa]=http://dvwa:80/
)
for name in juice-shop crapi webgoat dvwa; do
  url="${TARGETS[$name]}"
  mkdir -p "artifacts/$name"

  set +e
  docker run --rm --user 0:0 --network "$NETWORK" -v "$PWD/artifacts/$name:/zap/wrk/:rw" "$ZAP" zap-baseline.py -t "$url" -m 5 -I -r zap.html -J zap.json >"artifacts/$name/zap.log" 2>&1
  zap_rc=$?
  set -e
  case "$zap_rc" in 0|1) ;; *) echo "ZAP execution error for $name: $zap_rc"; exit "$zap_rc";; esac
  test -s "artifacts/$name/zap.json" || { echo "ZAP JSON report missing for $name" >&2; exit 1; }
  test -s "artifacts/$name/zap.html" || { echo "ZAP HTML report missing for $name" >&2; exit 1; }

  set +e
  docker run --rm --network "$NETWORK" -v "$TEMPLATE_DIR:/templates:ro" -v "$PWD/artifacts/$name:/out:rw" "$NUCLEI" -duc -t /templates -u "$url" -jsonl -o /out/nuclei.jsonl -silent -no-color -stats >"artifacts/$name/nuclei.log" 2>&1
  nuclei_rc=$?
  set -e
  if grep -Fq '[FTL]' "artifacts/$name/nuclei.log"; then
    echo "Nuclei fatal log detected for $name" >&2
    cat "artifacts/$name/nuclei.log" >&2
    exit 1
  fi
  if (( nuclei_rc != 0 )); then
    echo "Nuclei execution failed for $name with rc=$nuclei_rc" >&2
    cat "artifacts/$name/nuclei.log" >&2
    exit "$nuclei_rc"
  fi
  test -f "artifacts/$name/nuclei.jsonl" || { echo "Nuclei JSONL report missing for $name" >&2; exit 1; }
  python3 - "$name" <<'PY'
import json, sys
from pathlib import Path
name = sys.argv[1]
p = Path('artifacts') / name / 'nuclei.jsonl'
for lineno, line in enumerate(p.read_text().splitlines(), 1):
    if not line.strip():
        continue
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SystemExit(f'invalid Nuclei JSONL for {name}, line {lineno}: {exc}')
    if not isinstance(value, dict):
        raise SystemExit(f'invalid Nuclei JSONL object for {name}, line {lineno}')
print(f'nuclei_jsonl_valid={name}')
PY
done

python3 - <<'PY'
import json
from pathlib import Path

rules = [
    ('security-headers', ['header missing', 'security header', 'x-content-type', 'permissions policy']),
    ('cross-origin-policy', ['cross-origin']),
    ('cookies-and-session', ['cookie', 'session management']),
    ('csp-clickjacking-csrf', ['content security policy', 'anti-clickjacking', 'csrf', 'anti-csrf']),
    ('exposed-files-endpoints', ['robots', 'swagger', 'setup', 'configuration', 'env ', 'actuator', 'directory', 'public swagger', 'api']),
    ('technology-version-disclosure', ['version', 'technology', 'php detect', 'modern web', 'information disclosure', 'fingerprint', 'wappalyzer', 'server leaks']),
    ('javascript-xss', ['javascript', 'xss', 'dom']),
    ('authentication-authorization', ['auth', 'login', 'admin', 'authorization', 'bfla', 'idor']),
]

def category(text):
    low = text.lower()
    for name, needles in rules:
        if any(n in low for n in needles):
            return name
    return 'other'

def add(bucket, cat, item):
    bucket.setdefault(cat, []).append(item)

matrix = []
summary = {}
for d in sorted(Path('artifacts').iterdir()):
    if not d.is_dir():
        continue
    zap = json.loads((d/'zap.json').read_text())
    zap_by = {}
    for site in zap.get('site', []):
        for alert in site.get('alerts', []):
            text = alert.get('name') or alert.get('pluginid') or 'unknown'
            add(zap_by, category(text), f"{alert.get('riskdesc', 'unknown')}: {text}")
    nuclei_by = {}
    np = d/'nuclei.jsonl'
    for line in np.read_text().splitlines():
        if not line.strip():
            continue
        finding = json.loads(line)
        info = finding.get('info') or {}
        text = str(info.get('name') or finding.get('template-id') or 'unknown')
        add(nuclei_by, category(text), f"{info.get('severity', 'unknown')}: {text}")
    summary[d.name] = {
        'zap_total': sum(len(items) for items in zap_by.values()),
        'nuclei_total': sum(len(items) for items in nuclei_by.values()),
        'zap_by_category': {key: len(value) for key, value in sorted(zap_by.items())},
        'nuclei_by_category': {key: len(value) for key, value in sorted(nuclei_by.items())},
    }
    categories = sorted(set(zap_by) | set(nuclei_by))
    for cat in categories:
        z = zap_by.get(cat, [])
        n = nuclei_by.get(cat, [])
        matrix.append({
            'target': d.name,
            'category': cat,
            'zap_findings': z,
            'nuclei_findings': n,
            'evidence': {'zap': z[:8], 'nuclei': n[:8]},
            'gap': 'yes' if bool(z) != bool(n) else ('no' if z and n else 'none-observed'),
            'zap_mode': 'baseline',
        })
Path('artifacts/comparison-matrix.json').write_text(json.dumps(matrix, indent=2, sort_keys=True))
Path('artifacts/comparison-summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True))
lines = ['# ZAP baseline vs Nuclei comparison', '', '| Target | Category | ZAP | Nuclei | Evidence | Gap? |', '|---|---|---:|---:|---|---|']
for row in matrix:
    evidence = '<br>'.join((row['evidence']['zap'] + row['evidence']['nuclei'])[:4]).replace('|', '\\|')
    lines.append(f"| {row['target']} | {row['category']} | {len(row['zap_findings'])} | {len(row['nuclei_findings'])} | {evidence or 'none'} | {row['gap']} |")
Path('artifacts/comparison-table.md').write_text('\n'.join(lines) + '\n')
print('\n'.join(lines))
PY
