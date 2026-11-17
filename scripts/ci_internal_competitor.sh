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
WEBGOAT_VERSION=v2023.8
WEBGOAT='docker.io/webgoat/webgoat@sha256:01672eb9aeba60d042ae1131d6de683b98fa64e9da60fa5d3daad2642a6795dd'
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

mkdir -p artifacts
manual_probe() {
  local label="$1" base="$2" target_path="$3" random_path="$4"
  local out="artifacts/manual-${label}.json"
  python3 - "$label" "$base" "$target_path" "$random_path" "$out" "$ZAP" "$NETWORK" <<'PY'
import hashlib,json,subprocess,sys
label,base,target_path,random_path,out,zap,network=sys.argv[1:]
def fetch(path):
    url=base+path
    p=subprocess.run(['docker','run','--rm','--network',network,zap,'curl','-ksS','--max-time','15','-D','-','-o','-','-w','\nBURHAN_STATUS:%{http_code}\n',url],capture_output=True,text=False)
    raw=p.stdout; marker=b'\nBURHAN_STATUS:'
    head,_,tail=raw.rpartition(marker)
    status=tail.strip().splitlines()[0].decode('ascii','replace') if marker in raw else '000'
    body=head
    if b'\r\n\r\n' in body: body=body.split(b'\r\n\r\n',1)[1]
    return {'url':url,'status':int(status) if status.isdigit() else 0,
            'body_sha256':hashlib.sha256(body).hexdigest(),
            'first_200_bytes':body[:200].decode('utf-8','replace'),
            'body_length':len(body),'curl_rc':p.returncode,
            'wordpress_plugin_path_marker':(b'wp-content/plugins/' in body.lower() or b'wp-includes/' in body.lower() or b'wordpress' in body.lower())}
target=fetch(target_path); random=fetch(random_path)
same=(target['status']==random['status'] and target['body_sha256']==random['body_sha256'])
wp_false=(label=='webgoat-wordpress-plugin' and not target['wordpress_plugin_path_marker'])
result={'label':label,'target':target,'random_control':random,
        'likely_false_positive':(same or wp_false),
        'disposition':('إنذار كاذب مرجّح: لا توجد مؤشرات WordPress/plugin في جسم WebGoat' if wp_false else ('إنذار كاذب مرجّح: الهدف والمسار العشوائي متطابقان في الحالة والبصمة' if same else 'مختلف عن الضابط العشوائي'))}
open(out,'w').write(json.dumps(result,ensure_ascii=False,indent=2))
print(json.dumps(result,ensure_ascii=False))
PY
}
manual_probe crapi-env http://crapi-web:80 //.env //.-burhan-random-env
manual_probe webgoat-wordpress-plugin http://webgoat:8080 /WebGoat/login /WebGoat/login-burhan-random
printf 'webgoat_version=%s\nwebgoat_source=docker.io/webgoat/webgoat:%s (digest-pinned)\n' "$WEBGOAT_VERSION" "$WEBGOAT_VERSION" | tee artifacts/webgoat-version.txt

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
    spider_deadline=$((SECONDS + 120))
    spider_timed_out=0
    while (( SECONDS < spider_deadline )); do
      status="$(zap_api '/JSON/spider/view/status/' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","100"))')"
      [[ "$status" == 100 ]] && break
      sleep 3
    done
    if [[ "$status" != 100 ]]; then
      spider_timed_out=1
      echo "ZAP spider time limit reached for $name; continuing with bounded active scan" >&2
    fi
    zap_api '/JSON/ascan/action/scan/' --data-urlencode "url=$url" --data-urlencode 'recurse=true' --data-urlencode 'inScopeOnly=false' >/dev/null
    active_deadline=$((SECONDS + 180))
    active_timed_out=0
    while (( SECONDS < active_deadline )); do
      status="$(zap_api '/JSON/ascan/view/status/' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","100"))')"
      [[ "$status" == 100 ]] && break
      sleep 3
    done
    if [[ "$status" != 100 ]]; then
      active_timed_out=1
      echo "ZAP active scan time limit reached for $name; collecting bounded partial result" >&2
    fi
    zap_api '/JSON/core/view/numberOfMessages/' > "artifacts/$name/zap-active-messages.json"
    zap_api '/JSON/alert/view/alerts/' > "artifacts/$name/zap-active-alerts.json"
    end="$(date +%s)"
    python3 - "$name" "$start" "$end" "$spider_timed_out" "$active_timed_out" <<'PY'
import json,sys
from pathlib import Path
name,start,end=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
spider_timed_out=bool(int(sys.argv[4])); active_timed_out=bool(int(sys.argv[5]))
msg=json.loads((Path('artifacts')/name/'zap-active-messages.json').read_text())
alerts=json.loads((Path('artifacts')/name/'zap-active-alerts.json').read_text())
count=int(msg.get('numberOfMessages',0))
Path('artifacts',name,'zap-active-summary.json').write_text(json.dumps({
 'target':name,'mode':'active','duration_seconds':end-start,
 'request_count':count,'alert_count':len(alerts.get('alerts',[])),
 'spider_time_limit_seconds':120,'active_time_limit_seconds':180,
 'spider_timed_out':spider_timed_out,'active_timed_out':active_timed_out,
 'result_quality':'partial-time-bounded' if (spider_timed_out or active_timed_out) else 'complete'
 },indent=2))
PY
    python3 - "$name" <<'PY'
import json,sys
from pathlib import Path
name=sys.argv[1]
data=json.loads((Path('artifacts')/name/'zap-active-alerts.json').read_text())
def norm(a):
    n=str(a.get('name','')).lower()
    if any(x in n for x in ('anti-clickjacking','content security policy','x-content-type','permissions policy','cross-origin-opener','missing security headers')): return 'SECURITY_HEADERS'
    c=str(a.get('cweid') or '').strip()
    if c not in ('','0','-1'): return 'CWE-'+c.replace('CWE-','')
    return 'NO-CWE|WASC-'+str(a.get('wascid') or '-1')
rows=[]
RISK_BY_NAME={
 'missing anti-clickjacking header':'medium','content security policy (csp) header not set':'medium',
 'server leaks version information via "server" http response header field':'low',
 'x-content-type-options header missing':'low','cross-origin-resource-policy header missing or invalid':'low',
 'cross-origin-opener-policy header missing or invalid':'low','cross-origin-embedder-policy header missing or invalid':'low',
 'cookie no httponly flag':'low','cookie without samesite attribute':'low','permissions policy header not set':'low',
 'dangerous js functions':'low','deprecated feature policy header set':'low',
 'apache http server version with known vulnerabilities':'high','absence of anti-csrf tokens':'medium',
 'cross-domain misconfiguration':'medium','session id in url rewrite':'medium'
}
for a in data.get('alerts',[]):
    sev=RISK_BY_NAME.get(str(a.get('name','')).lower(),'info')
    if sev.startswith('inform'): sev='info'
    rows.append({'severity':sev,'standard_type':norm(a),'cwe':a.get('cweid'),'path':a.get('uri'),'name':a.get('name')})
Path('artifacts',name,'zap-active-types.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False))
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
BAD_PATHS={"/static/js/'),B=f('","/{{href}}"}
def severity(value,source=''):
    s=str(value or '').lower().strip()
    if source=='zap' and '(' in s: s=s.split('(',1)[0].strip()
    return s if s in SEVERITIES else 'info'
def path_of(value):
    raw=str(value or ''); parsed=urlsplit(raw)
    return parsed.path or raw.split('?',1)[0] or '/'
def values(value):
    if value is None:return []
    if isinstance(value,list):return [str(x).strip() for x in value if str(x).strip()]
    return [str(value).strip()] if str(value).strip() else []
def cwe(cwes):
    out=[]
    for item in values(cwes):
        item=item.upper().replace('CWE-','').strip()
        if item not in ('','0','-1','NONE','NULL'):out.append(f'CWE-{item}')
    return '|'.join(sorted(set(out)))
def norm(source,name='',cwes=None,burhan_type=''):
    n=str(name).lower()
    if burhan_type=='missing_security_headers' or any(x in n for x in ('anti-clickjacking','content security policy','x-content-type','permissions policy','cross-origin-opener','missing security headers')): return 'SECURITY_HEADERS'
    if burhan_type=='server_banner_disclosure' or 'server leaks version' in n:return 'SERVER_BANNER_DISCLOSURE'
    if burhan_type=='weak_random':return 'CWE-330'
    if burhan_type=='host_header_injection':return 'CWE-644'
    return cwe(cwes) or (f'NO-CWE|{source.upper()}:{burhan_type or name or "unknown"}')
def add(store,sev,typ,path,evidence):
    if path in BAD_PATHS:return
    store.setdefault(sev,{}).setdefault(typ,{})[path]=evidence
def zap_records(d):
    out={}; data=json.loads((d/'zap.json').read_text())
    for site in data.get('site',[]):
      for a in site.get('alerts',[]):
        name=a.get('name') or a.get('pluginid') or 'unknown'
        add(out,severity(a.get('riskdesc') or a.get('riskcode'),'zap'),norm('zap',name,a.get('cweid')),path_of(a.get('uri') or site.get('@name')),name)
    return out
def probe_disposition():
    out={}
    for p in Path('artifacts').glob('manual-*.json'):
        try:
            d=json.loads(p.read_text()); out[d['label']]=d
        except Exception: pass
    return out
def nuclei_records(d):
    out={}; probes=probe_disposition(); labels={'laravel-env':'crapi-env','generic-env':'crapi-env','codeigniter-env':'crapi-env','wordpress-plugin-detect':'webgoat-wordpress-plugin'}
    for line in (d/'nuclei.jsonl').read_text().splitlines():
      if not line.strip():continue
      f=json.loads(line); info=f.get('info') or {}; tid=f.get('template-id','unknown'); cls=info.get('classification') or {}
      ev=str(info.get('name') or tid)
      if labels.get(tid) in probes and probes[labels[tid]].get('likely_false_positive'): ev+=' (إنذار كاذب مرجّح: مطابق للضابط العشوائي)'
      add(out,severity(info.get('severity'),'nuclei'),norm('nuclei',info.get('name'),cls.get('cwe-id')),path_of(f.get('matched-at') or f.get('host') or f.get('url')),ev)
    return out
def burhan_records(d):
    out={}; data=json.loads((d/'burhan.json').read_text())
    for f in data.get('findings',[]):
      typ=f.get('type','unknown'); add(out,severity(f.get('severity'),'burhan'),norm('burhan','',[(f.get('compliance') or {}).get('cwe')],typ),path_of(f.get('url')),typ)
    return out
matrix=[]; summary={}; excluded=0
for d in sorted(Path('artifacts').iterdir()):
    if not d.is_dir() or not (d/'zap.json').exists():continue
    tools={'zap':zap_records(d),'nuclei':nuclei_records(d),'burhan':burhan_records(d)}; summary[d.name]={}
    for tool,records in tools.items():
      summary[d.name][tool]={}
      for sev in SEVERITIES:
        groups=records.get(sev,{})
        summary[d.name][tool][sev]={'distinct_types':len(groups),'paths':sum(len(v) for v in groups.values())}
      summary[d.name][tool]['total_types']=len({t for sev in SEVERITIES for t in records.get(sev,{})})
      summary[d.name][tool]['total_paths']=sum(len(v) for sev in SEVERITIES for v in records.get(sev,{}).values())
    for sev in SEVERITIES:
      types=set().union(*(tools[t].get(sev,{}) for t in tools))
      for typ in sorted(types):
        groups={t:tools[t].get(sev,{}).get(typ,{}) for t in tools}
        zpaths=sorted(groups['zap']); npaths=sorted(groups['nuclei']); bpaths=sorted(groups['burhan'])
        ev=sorted(set(list(groups['zap'].values())+list(groups['nuclei'].values())+list(groups['burhan'].values())))
        gap=sev!='info' and bool(zpaths or npaths) and not bpaths
        matrix.append({'target':d.name,'severity':sev,'standard_type':typ,'zap_paths':zpaths,'nuclei_paths':npaths,'burhan_paths':bpaths,'evidence':ev,'gap_for_burhan':gap,'info_is_vulnerability':sev!='info','zap_mode':'baseline'})
    raw=json.loads((d/'burhan.json').read_text())
    excluded+=sum(1 for f in raw.get('findings',[]) if path_of(f.get('url')) in BAD_PATHS)
summary['_normalization']={'excluded_extracted_paths_count':excluded,'excluded_paths':sorted(BAD_PATHS),'burhan_grouping':'distinct standard_type with path counts'}
Path('artifacts/comparison-matrix.json').write_text(json.dumps(matrix,indent=2,sort_keys=True,ensure_ascii=False))
Path('artifacts/comparison-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True,ensure_ascii=False))
lines=['# ZAP baseline vs Nuclei vs Burhan proof','', '| Target | Severity | Standard type | ZAP paths | Nuclei paths | Burhan paths | Evidence | Gap for Burhan? |','|---|---|---|---:|---:|---:|---|---|']
for r in matrix:
  ev='<br>'.join(sorted(set(r['evidence']))).replace('|','\\|') or 'none'
  lines.append(f"| {r['target']} | {r['severity']} | {r['standard_type']} | {len(r['zap_paths'])} | {len(r['nuclei_paths'])} | {len(r['burhan_paths'])} | {ev} | {'yes' if r['gap_for_burhan'] else 'no'} |")
Path('artifacts/comparison-table.md').write_text('\n'.join(lines)+'\n'); print('\n'.join(lines))
PY
