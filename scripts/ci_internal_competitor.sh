#!/usr/bin/env bash
set -euo pipefail

NETWORK=burhan-dev
CRAPI_COMMIT=700f03d12a392d9e408260b4beae72ed02a4a1a4
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

docker pull "$ZAP"
docker pull "$NUCLEI"
mkdir -p artifacts
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
  docker run --rm --user 0:0 --network "$NETWORK" -v "$PWD/artifacts/$name:/zap/wrk/:rw" "$ZAP" zap-baseline.py -t "$url" -m 5 -I -r zap.html -J zap.json
  zap_rc=$?
  docker run --rm --network "$NETWORK" -v "$PWD/artifacts/$name:/out:rw" "$NUCLEI" -u "$url" -jsonl -o /out/nuclei.jsonl -silent -no-color
  nuclei_rc=$?
  set -e
  case "$zap_rc" in 0|1) ;; *) echo "ZAP execution error for $name: $zap_rc"; exit "$zap_rc";; esac
  case "$nuclei_rc" in 0|1) ;; *) echo "Nuclei execution error for $name: $nuclei_rc"; exit "$nuclei_rc";; esac
  test -s "artifacts/$name/zap.json" || { echo "ZAP JSON report missing for $name" >&2; exit 1; }
  test -s "artifacts/$name/zap.html" || { echo "ZAP HTML report missing for $name" >&2; exit 1; }
done

python3 - <<'PY'
import json
from pathlib import Path
out = {}
for d in sorted(Path('artifacts').iterdir()):
    if not d.is_dir():
        continue
    zap = json.loads((d/'zap.json').read_text()) if (d/'zap.json').exists() else {}
    zap_counts = {}
    for site in zap.get('site', []):
        for alert in site.get('alerts', []):
            risk = (alert.get('riskdesc') or 'unknown').split(' ')[0].lower()
            name = alert.get('name') or alert.get('pluginid') or 'unknown'
            zap_counts[f'{risk}:{name}'] = zap_counts.get(f'{risk}:{name}', 0) + 1
    nuclei_counts = {}
    p = d/'nuclei.jsonl'
    if p.exists():
        for line in p.read_text().splitlines():
            if not line.strip():
                continue
            x = json.loads(line)
            info = x.get('info') or {}
            sev = str(info.get('severity') or 'unknown').lower()
            name = str(info.get('name') or x.get('template-id') or 'unknown')
            nuclei_counts[f'{sev}:{name}'] = nuclei_counts.get(f'{sev}:{name}', 0) + 1
    out[d.name] = {
        'zap_total': sum(zap_counts.values()),
        'nuclei_total': sum(nuclei_counts.values()),
        'zap_by_category_severity': zap_counts,
        'nuclei_by_category_severity': nuclei_counts,
        'common_normalized_keys': sorted(set(zap_counts) & set(nuclei_counts)),
    }
Path('artifacts/comparison-summary.json').write_text(json.dumps(out, indent=2, sort_keys=True))
print(json.dumps({k: {'zap_total': v['zap_total'], 'nuclei_total': v['nuclei_total'], 'common': len(v['common_normalized_keys'])} for k,v in out.items()}, indent=2))
PY
