#!/usr/bin/env bash
set -euo pipefail

NETWORK=burhan-dev
CRAPI_COMMIT=700f03d12a392d9e408260b4beae72ed02a4a1a4
TEMPLATE_DIR="${NUCLEI_TEMPLATE_DIR:-$PWD/.ci/nuclei-templates}"
TEMPLATE_COUNT_FILE="${NUCLEI_TEMPLATE_COUNT_FILE:-$PWD/.ci/nuclei-template-count}"
TEMPLATE_ARCHIVE="${NUCLEI_TEMPLATE_ARCHIVE:-/tmp/nuclei-templates.tar.gz}"
TEMPLATE_SHA256_EXPECTED=80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41
TEMPLATE_COMMIT=f8b8b8dcd70d93826c3767e1829ef8243af9f03b
JUICE='docker.io/bkimminich/juice-shop@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27'
WEBGOAT='docker.io/webgoat/webgoat@sha256:2775102b8186df1656f8a69cfb7a6bf6c77b43a25fa0accd6d44e6ae04c8d3b7'
DVWA='docker.io/vulnerables/web-dvwa@sha256:14c929ec1a99edb77326201f7f0fb431d1b3dd099c09ddeaf46312ab0ff53cfe'
ZAP='docker.io/zaproxy/zap-stable@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af'
NUCLEI='docker.io/projectdiscovery/nuclei@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97'
ACTIVE_ZAP_ONLY="${ACTIVE_ZAP_ONLY:-0}"

cleanup() {
  docker rm -f zap-active 2>/dev/null || true
  docker compose -p crapi -f /tmp/crapi-compose.yml down -v --remove-orphans 2>/dev/null || true
  docker rm -f dev-juice dev-webgoat dev-dvwa 2>/dev/null || true
  docker network rm "$NETWORK" 2>/dev/null || true
}
trap cleanup EXIT

if [[ "$ACTIVE_ZAP_ONLY" != 1 ]]; then
  test -d "$TEMPLATE_DIR" || { echo "Nuclei template directory missing" >&2; exit 1; }
  test -s "$TEMPLATE_COUNT_FILE" || { echo "Nuclei template count file missing" >&2; exit 1; }
  test -s "$TEMPLATE_ARCHIVE" || { echo "Nuclei template archive missing" >&2; exit 1; }
  TEMPLATE_SHA256_COMPUTED="$(sha256sum "$TEMPLATE_ARCHIVE" | awk '{print $1}')"
  test "$TEMPLATE_SHA256_COMPUTED" = "$TEMPLATE_SHA256_EXPECTED" || {
    echo "Nuclei template archive SHA-256 mismatch" >&2; exit 1;
  }
  TEMPLATE_COUNT="$(cat "$TEMPLATE_COUNT_FILE")"
  case "$TEMPLATE_COUNT" in ''|*[!0-9]*) echo "invalid template count" >&2; exit 1;; esac
  (( TEMPLATE_COUNT > 0 )) || { echo "zero Nuclei templates loaded" >&2; exit 1; }
  printf 'nuclei_templates_version=v10.5.0\n'
  printf 'nuclei_templates_commit=%s\n' "$TEMPLATE_COMMIT"
  printf 'nuclei_templates_tar_sha256_computed=%s\n' "$TEMPLATE_SHA256_COMPUTED"
  printf 'nuclei_templates_loaded=%s\n' "$TEMPLATE_COUNT"
  docker pull "$NUCLEI"
  docker run --rm --network host -v "$TEMPLATE_DIR:/templates:ro" "$NUCLEI" -duc -t /templates -tl > /tmp/nuclei-template-list.txt 2>/tmp/nuclei-template-list.log
  RUNTIME_TEMPLATE_COUNT="$(wc -l < /tmp/nuclei-template-list.txt | tr -d ' ')"
  printf 'nuclei_runtime_templates_listed=%s\n' "$RUNTIME_TEMPLATE_COUNT"
  (( RUNTIME_TEMPLATE_COUNT > 0 )) || { cat /tmp/nuclei-template-list.log >&2; exit 1; }
else
  RUNTIME_TEMPLATE_COUNT=0
  TEMPLATE_COUNT=0
  TEMPLATE_SHA256_COMPUTED=""
fi

docker pull "$ZAP"
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

TARGETS=(juice-shop crapi webgoat dvwa)
declare -A INTERNAL_TARGETS=(
  [juice-shop]=http://juice-shop:3000/
  [crapi]=http://crapi-web:80/
  [webgoat]=http://webgoat:8080/WebGoat/
  [dvwa]=http://dvwa:80/
)
declare -A HOST_TARGETS=(
  [juice-shop]=http://127.0.0.1:3000/
  [crapi]=http://127.0.0.1:8888/
  [webgoat]=http://127.0.0.1:8080/WebGoat/
  [dvwa]=http://127.0.0.1:8081/
)
mkdir -p artifacts

if [[ "$ACTIVE_ZAP_ONLY" == 1 ]]; then
  echo 'burhan_mode=internal-lab-active-zap'
  for name in "${TARGETS[@]}"; do
    url="${INTERNAL_TARGETS[$name]}"
    mkdir -p "artifacts/$name"
    start="$(date +%s)"
    api_key=burhan-active-ci
    docker run -d --user zap --name zap-active --network "$NETWORK" "$ZAP" zap.sh -daemon -host 0.0.0.0 -port 8080 -config "api.key=$api_key" -config 'api.addrs.addr.name=.*' -config api.addrs.addr.regex=true >/dev/null
    zap_api() {
      local endpoint="$1"; shift
      docker exec zap-active curl -fsS --get "http://127.0.0.1:8080${endpoint}" \
        --data-urlencode "apikey=$api_key" "$@"
    }
    ready=$((SECONDS + 90))
    until docker logs zap-active 2>/dev/null | grep -Fq 'ZAP is now listening on 0.0.0.0:8080'; do
      if (( SECONDS >= ready )); then
        docker logs zap-active > "artifacts/$name/zap-active-daemon.log" 2>&1 || true
        echo "ZAP API did not become ready for $name" >&2
        exit 1
      fi
      sleep 2
    done
    zap_api '/JSON/core/view/version/' >/dev/null
    zap_api '/JSON/spider/action/scan/' --data-urlencode "url=$url" --data-urlencode 'recurse=true' >/dev/null
    deadline=$((SECONDS + 180))
    while (( SECONDS < deadline )); do
      status="$(zap_api '/JSON/spider/view/status/' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","100"))')"
      [[ "$status" == 100 ]] && break
      sleep 3
    done
    test "$status" = 100 || { docker logs zap-active > "artifacts/$name/zap-active-daemon.log" 2>&1 || true; echo "ZAP spider time limit exceeded for $name" >&2; exit 1; }
    zap_api '/JSON/ascan/action/scan/' --data-urlencode "url=$url" --data-urlencode 'recurse=true' --data-urlencode 'inScopeOnly=false' >/dev/null
    while (( SECONDS < deadline )); do
      status="$(zap_api '/JSON/ascan/view/status/' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","100"))')"
      [[ "$status" == 100 ]] && break
      sleep 3
    done
    test "$status" = 100 || { echo "active scan time limit exceeded for $name" >&2; exit 1; }
    zap_api '/JSON/core/view/numberOfMessages/' > "artifacts/$name/zap-active-messages.json"
    zap_api '/JSON/alert/view/alerts/' > "artifacts/$name/zap-active-alerts.json"
    end="$(date +%s)"
    python3 - "$name" "$start" "$end" <<'PY'
import json,sys
from pathlib import Path
name,start,end=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
msg=json.loads((Path('artifacts')/name/'zap-active-messages.json').read_text())
alerts=json.loads((Path('artifacts')/name/'zap-active-alerts.json').read_text())
count=int(msg.get('numberOfMessages',0))
Path('artifacts',name,'zap-active-summary.json').write_text(json.dumps({
 'target':name,'mode':'active','duration_seconds':end-start,
 'request_count':count,'alert_count':len(alerts.get('alerts',[])),
 'time_limit_seconds':180
},indent=2))
PY
    docker rm -f zap-active >/dev/null
  done
  exit 0
fi

if [[ -z "${BURHAN_OWNER_PASSWORD:-}" ]]; then
  echo 'ephemeral BURHAN_OWNER_PASSWORD environment value is required; no scan started' >&2
  exit 2
fi
OWNER_GATE="${BURHAN_OWNER_GATE:-${RUNNER_TEMP:-/tmp}/burhan-owner-gate.json}"
rm -f "$OWNER_GATE"
mkdir -p "$(dirname "$OWNER_GATE")"
export BURHAN_OWNER_GATE="$OWNER_GATE"
python3 -m burhan.cli owner init >/dev/null
cleanup_owner() {
  rm -f "$OWNER_GATE"
  unset BURHAN_OWNER_PASSWORD
  cleanup
}
trap cleanup_owner EXIT
PROOF_SEED='burhan-m3-fixed-proof-seed-2026-11-16-00000000000000000000000000000000'
echo 'burhan_mode=internal-lab-proof'
echo 'burhan_proof_seed=fixed'

cat > artifacts/nuclei-run-metadata.json <<EOF
{
  "engine_image": "$NUCLEI",
  "templates_version": "v10.5.0",
  "templates_commit": "$TEMPLATE_COMMIT",
  "templates_tar_sha256_computed": "$TEMPLATE_SHA256_COMPUTED",
  "templates_loaded": $TEMPLATE_COUNT,
  "runtime_templates_listed": $RUNTIME_TEMPLATE_COUNT,
  "scan_mode": "Nuclei HTTP templates; no ZAP active scan"
}
EOF

for name in "${TARGETS[@]}"; do
  url="${INTERNAL_TARGETS[$name]}"
  host_url="${HOST_TARGETS[$name]}"
  mkdir -p "artifacts/$name"

  BURHAN_OWNER_GATE="$OWNER_GATE" BURHAN_OWNER_PASSWORD="$BURHAN_OWNER_PASSWORD" \
    python3 -m burhan.cli scan "$host_url" --allow-private --no-oast --no-browser \
      --seed "$PROOF_SEED" --max-pages 25 --timeout 12 \
      --owner-gate "$OWNER_GATE" --out "artifacts/$name/burhan.json" \
      >"artifacts/$name/burhan.log" 2>&1
  python3 - "$name" <<'PY'
import json,sys
from pathlib import Path
name=sys.argv[1]; p=Path('artifacts')/name/'burhan.json'
r=json.loads(p.read_text())
if not isinstance(r.get('findings'),list): raise SystemExit(f'invalid Burhan proof JSON: {name}')
print(f'burhan_json_valid={name}')
PY

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
    echo "Nuclei fatal log detected for $name" >&2; cat "artifacts/$name/nuclei.log" >&2; exit 1
  fi
  if (( nuclei_rc != 0 )); then
    echo "Nuclei execution failed for $name with rc=$nuclei_rc" >&2; cat "artifacts/$name/nuclei.log" >&2; exit "$nuclei_rc"
  fi
  test -f "artifacts/$name/nuclei.jsonl" || { echo "Nuclei JSONL report missing for $name" >&2; exit 1; }
  python3 - "$name" <<'PY'
import json,sys
from pathlib import Path
name=sys.argv[1]; p=Path('artifacts')/name/'nuclei.jsonl'
for lineno,line in enumerate(p.read_text().splitlines(),1):
    if line.strip():
        value=json.loads(line)
        if not isinstance(value,dict): raise SystemExit(f'invalid Nuclei JSONL object: {name}:{lineno}')
print(f'nuclei_jsonl_valid={name}')
PY
done

leak_list="$(mktemp)"
if grep -R -F -l -- "$BURHAN_OWNER_PASSWORD" artifacts >"$leak_list" 2>/dev/null; then
  echo 'ephemeral owner credential found in artifacts; refusing success' >&2
  rm -f "$leak_list"
  exit 1
fi
rm -f "$leak_list"

python3 - <<'PY'
import json
from pathlib import Path
from urllib.parse import urlsplit

SEVERITIES=('critical','high','medium','low','info')

def severity(value, source=''):
    s=str(value or '').lower().strip()
    if source=='zap' and '(' in s: s=s.split('(',1)[0].strip()
    return s if s in SEVERITIES else 'info'

def path_of(value):
    raw=str(value or '')
    parsed=urlsplit(raw)
    return parsed.path or raw.split('?',1)[0] or '/'

def values(value):
    if value is None: return []
    if isinstance(value,list): return [str(x).strip() for x in value if str(x).strip()]
    return [str(value).strip()] if str(value).strip() else []

def cwe_type(cwes, fallback):
    clean=[]
    for item in values(cwes):
        item=item.upper().replace('CWE-','').strip()
        if item not in ('','0','-1','NONE','NULL'): clean.append(f'CWE-{item}')
    return '|'.join(sorted(set(clean))) if clean else fallback

def add(store, sev, typ, path, evidence):
    store.setdefault(sev,{})[(typ,path)] = evidence

def zap_records(d):
    out={}
    data=json.loads((d/'zap.json').read_text())
    for site in data.get('site',[]):
        for alert in site.get('alerts',[]):
            name=alert.get('name') or alert.get('pluginid') or 'unknown'
            cwe=alert.get('cweid')
            wasc=alert.get('wascid')
            fallback=f"NO-CWE|WASC-{wasc}" if str(wasc or '').strip() not in ('','0') else f"NO-CWE|ZAP:{alert.get('pluginid') or name}"
            typ=cwe_type(cwe,fallback)
            add(out,severity(alert.get('riskdesc') or alert.get('riskcode'),'zap'),typ,path_of(alert.get('uri') or site.get('@name')),name)
    return out

def nuclei_records(d):
    out={}
    for line in (d/'nuclei.jsonl').read_text().splitlines():
        if not line.strip(): continue
        finding=json.loads(line); info=finding.get('info') or {}
        cls=info.get('classification') or {}
        tags=values(info.get('tags'))
        fallback=f"NO-CWE|NUCLEI-TAGS:{','.join(sorted(set(tags))) or 'none'}|{finding.get('template-id','unknown')}"
        typ=cwe_type(cls.get('cwe-id'),fallback)
        add(out,severity(info.get('severity'),'nuclei'),typ,path_of(finding.get('matched-at') or finding.get('host') or finding.get('url')),str(info.get('name') or finding.get('template-id') or 'unknown'))
    return out

def burhan_records(d):
    out={}; data=json.loads((d/'burhan.json').read_text())
    for finding in data.get('findings',[]):
        typ=cwe_type(finding.get('cwe') or finding.get('cwe_id'),f"NO-CWE|BURHAN:{finding.get('type','unknown')}")
        add(out,severity(finding.get('severity'),'burhan'),typ,path_of(finding.get('url')),str(finding.get('type','unknown')))
    return out

matrix=[]; summary={}
for d in sorted(Path('artifacts').iterdir()):
    if not d.is_dir() or not (d/'zap.json').exists(): continue
    tools={'zap':zap_records(d),'nuclei':nuclei_records(d),'burhan':burhan_records(d)}
    summary[d.name]={}
    for tool,records in tools.items():
        summary[d.name][tool]={sev:len(records.get(sev,{})) for sev in SEVERITIES}
        summary[d.name][tool]['total']=sum(len(records.get(sev,{})) for sev in SEVERITIES)
    for sev in SEVERITIES:
        keys=set().union(*(tools[t].get(sev,{}) for t in tools))
        for typ,path in sorted(keys):
            z=tools['zap'].get(sev,{}).get((typ,path)); n=tools['nuclei'].get(sev,{}).get((typ,path)); b=tools['burhan'].get(sev,{}).get((typ,path))
            gap=(sev!='info' and (z is not None or n is not None) and b is None)
            matrix.append({'target':d.name,'severity':sev,'standard_type':typ,'path':path,'zap':z is not None,'nuclei':n is not None,'burhan':b is not None,'evidence':{'zap':z,'nuclei':n,'burhan':b},'gap_for_burhan':gap,'info_is_vulnerability':False if sev=='info' else True,'zap_mode':'baseline'})
Path('artifacts/comparison-matrix.json').write_text(json.dumps(matrix,indent=2,sort_keys=True))
Path('artifacts/comparison-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True))
lines=['# ZAP baseline vs Nuclei vs Burhan proof','', '| Target | Severity | Standard type | Path | ZAP | Nuclei | Burhan proof | Evidence | Gap for Burhan? |','|---|---|---|---|---:|---:|---:|---|---|']
for row in matrix:
    ev='<br>'.join(f"{k}: {v}" for k,v in row['evidence'].items() if v).replace('|','\\|') or 'none'
    lines.append(f"| {row['target']} | {row['severity']} | {row['standard_type']} | {row['path']} | {int(row['zap'])} | {int(row['nuclei'])} | {int(row['burhan'])} | {ev} | {'yes' if row['gap_for_burhan'] else 'no'} |")
Path('artifacts/comparison-table.md').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines))
PY
