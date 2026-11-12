#!/usr/bin/env bash
# PHASEC L1 step 0b — bring up sealed isolated-set candidates on an
# INTERNAL docker network (owner rule 2026-11-11 §5.1/7: no outside egress
# for the cloned app code once pull/build is done) and prove readiness
# FROM THE SAME NETWORK PATH a scan would use (run-41286864928 lesson:
# probe from a container on the target network inside the dind, never
# from the job runner).
#
# Usage: bash phasec_step_zero_up.sh [candidate ...]
#   candidates: shepherd railsgoat vampi xvwa wackopicko (default: all)
#
# Sources verified from the pinned clones (docs-first, 2026-11-11):
#   shepherd    docker-compose.yml services: web/db/mongo; .env IS tracked
#               at the pinned commit; probe the service name "web" (tomcat,
#               port 8080 — HTTP_PORT maps 80:8080 host-side only).
#               The compose build COPIES maven outputs (target/*.war +
#               docker/*/target/*.sql|js — README:19 "mvn -Pdocker clean
#               package -DskipTests"); run that build FIRST inside a
#               digest-pinned maven container (fix 2026-11-12, run
#               43128061378 BLOCKED: COPY target/*.war failed).
#   railsgoat   docker-compose.yml: single service "web", port 3000.
#               Base ruby:2.5.0 apt's against EOL debian stretch -> 404
#               (run 43128061378 BLOCKED); patched to archive.debian.org
#               pre-build (fix 2026-11-12) — same minimal-patch style as
#               the XVWA config.php patch. TLS to rubygems.org verified OK
#               against the stretch CA store (GlobalSign Root R3 present,
#               openssl verify OK 2026-11-12) so `bundle install` works;
#               ca-certificates refresh from the archive kept as belt-and-
#               braces because that root is near its 2028 expiry.
#   vampi       official image erev0s/vampi; env var is "vulnerable"
#               (0/1) per README docker-run example; SINGLE port 5000 for
#               BOTH twins (safe/unsafe run as two containers); swagger /ui.
#   xvwa        no official image (seal notes); own LAMP: php:8.1-apache +
#               mysql sibling; config.php points at "localhost" — patched
#               to the db service name on the internal net.
#   wackopicko  official image adamdoupe/wackopicko, port 80, digest-pinned.
#
# FAILURES DO NOT ABORT THE MATRIX: a failed candidate gets a BLOCKED
# record (owner rule §5.1/5) and the loop continues.

set -u
OUT="${GITHUB_WORKSPACE:-.}/phasec-step-zero"
SEAL_DIR="${GITHUB_WORKSPACE:-.}/download/phaseC/seal"
mkdir -p "$OUT"

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }

pinned_commit() { # app key -> full 40-char commit from its seal manifest
  python3 - "$SEAL_DIR" "$1" <<'PY'
import json, pathlib, sys
d = json.loads((pathlib.Path(sys.argv[1]) / f"{sys.argv[2]}-reference.json").read_text())
print(d["pinned_commit"])
PY
}

record_blocked() { # name rc reason
  local name="$1" rc="$2" reason="$3"
  cat > "$OUT/BLOCKED-$name.md" <<EOF
# BLOCKED — $name

- exit: $rc
- reason: $reason
- date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- rule: owner 2026-11-11 §5.1/5 — replacement candidate (sqli-labs, then
  owasp-skf) is a separate decision with a NEW seal commit; this record
  only documents the failure.
EOF
  log "BLOCKED recorded: $name ($reason)"
}

ensure_net() {
  docker network create --internal phasec-iso 2>/dev/null || true
}

probe() { # name url -> 0 when HTTP code is 2xx/3xx/4xx (alive)
  local name="$1" url="$2" code
  code=$(docker run --rm --network phasec-iso curlimages/curl:8.11.1 \
    -s -o /dev/null -w "%{http_code}" --max-time 20 "$url" 2>/dev/null)
  printf '%s' "$code" > "$OUT/$name.probe"
  [ "$code" -ge 200 ] 2>/dev/null && [ "$code" -lt 500 ] 2>/dev/null
}

wait_ready() { # name url attempts sleep_s
  local name="$1" url="$2" i
  for i in $(seq 1 "${3:-30}"); do
    probe "$name" "$url" && return 0
    sleep "${4:-15}"
  done
  return 1
}

up_shepherd() {
  local commit; commit=$(pinned_commit security-shepherd)
  log "shepherd: clone @${commit:0:12}…"
  rm -rf /tmp/shepherd
  git clone --quiet https://github.com/OWASP/SecurityShepherd.git /tmp/shepherd || return 1
  git -C /tmp/shepherd checkout --quiet "$commit" || return 1
  cd /tmp/shepherd || return 1
  # .env is tracked at the pinned commit (verified 2026-11-11).
  [ -f .env ] || { echo "no .env at pinned commit" > "$OUT/shepherd.up.log"; return 1; }
  # Build the maven outputs the compose Dockerfiles COPY (README:19).
  # Digest-pinned maven (matches the release=17 compiler in pom.xml);
  # -o would break on a cold cache, full download it is. .mvn/maven.config
  # and mvnw are tracked at the pinned commit — use the wrapper's settings.
  docker run --rm --network host -v "$PWD":/src -w /src \
    maven@sha256:1a352420f7aba21f5ad08df31bab55f74c013fb491f1ae8ab1dd7ff9ed698584 \
    mvn -Pdocker clean package -DskipTests -q \
    >> "$OUT/shepherd.up.log" 2>&1 \
    || { echo "maven build failed" >> "$OUT/shepherd.up.log"; return 1; }
  # the three artifacts the Dockerfiles expect
  { [ -f target/owaspSecurityShepherd.war ] \
    && [ -f docker/mariadb/target/coreSchema.sql ] \
    && [ -f docker/mongo/target/moduleSchemas.js ]; } \
    || { echo "maven outputs missing after build" >> "$OUT/shepherd.up.log"; return 1; }
  # bridge the compose default network onto the egress-free internal net
  cat > docker-compose.override.yml <<'YAML'
networks:
  default:
    name: phasec-iso
    external: true
YAML
  docker compose up -d --build > "$OUT/shepherd.up.log.2" 2>&1 || { cat "$OUT/shepherd.up.log.2" >> "$OUT/shepherd.up.log"; return 1; }
  cat "$OUT/shepherd.up.log.2" >> "$OUT/shepherd.up.log"
  # service is "web" (tomcat) on container port 8080 (probe goes
  # service-to-service on the internal net; host port mappings are
  # irrelevant inside the dind)
  wait_ready shepherd "http://web:8080/" 40 15
  return $?
}

up_railsgoat() {
  local commit; commit=$(pinned_commit railsgoat)
  log "railsgoat: clone @${commit:0:12}…"
  rm -rf /tmp/railsgoat
  git clone --quiet https://github.com/smDahlgren/RailGoat.git /tmp/railsgoat || return 1
  git -C /tmp/railsgoat checkout --quiet "$commit" || return 1
  cd /tmp/railsgoat || return 1
  # ruby:2.5.0's apt points at EOL debian stretch (404 everywhere, run
  # 43128061378). Patch sources.list to archive.debian.org BEFORE the
  # image build, pre-installing a fresh ca-certificates from the archive
  # too (belt-and-braces for rubygems TLS; the stretch store already
  # verifies the live chain OK — 2026-11-12).
  # same minimal-patch style as the XVWA config.php sed patch — but done
  # via a small python heredoc so quoting stays auditable (run-43188415114
  # taught: patch(1) needs -p1 for a/ b/ headers; python needs neither).
  # Fails closed: any of grep-guard, replace-count!=1, or final check
  # blocks the candidate with a distinct reason.
  python3 - <<'PY' > "$OUT/railsgoat.up.log" 2>&1 || { echo "Dockerfile patch step failed" >> "$OUT/railsgoat.up.log"; return 1; }
import pathlib
f = pathlib.Path("Dockerfile")
t = f.read_text()
OLD = "RUN apt-get update -qq && apt-get install -y build-essential libpq-dev nodejs"
NEW = ("RUN printf 'deb http://archive.debian.org/debian stretch main\\n"
       "deb http://archive.debian.org/debian-security stretch/updates main\\n' > /etc/apt/sources.list \\\n"
       "    && apt-get -o Acquire::Check-Valid-Until=false update -qq \\\n"
       "    && apt-get install -y --no-install-recommends ca-certificates \\\n"
       "    && apt-get install -y build-essential libpq-dev nodejs")
if t.count(OLD) != 1:
    raise SystemExit(f"Dockerfile apt line count != 1 (got {t.count(OLD)}) at pinned commit")
f.write_text(t.replace(OLD, NEW))
if "archive.debian.org" not in f.read_text():
    raise SystemExit("post-patch check failed: archive line absent")
print("Dockerfile patched: stretch -> archive.debian.org")
PY
  cat > docker-compose.override.yml <<'YAML'
networks:
  default:
    name: phasec-iso
    external: true
YAML
  docker compose up -d --build > "$OUT/railsgoat.up.log" 2>&1 || return 1
  wait_ready railsgoat "http://web:3000/" 40 15
  return $?
}

up_vampi() {
  # official image, digest-pinned in the seal; env var "vulnerable"
  # (README: docker run -e vulnerable=0 ...); single port 5000 per twin.
  log "vampi: official image (digest-pinned in seal)"
  docker run -d --name vampi-unsafe --network phasec-iso \
    -e vulnerable=1 erev0s/vampi@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12 \
    > "$OUT/vampi.up.log" 2>&1 || return 1
  docker run -d --name vampi-safe --network phasec-iso \
    -e vulnerable=0 erev0s/vampi@sha256:0a5a224b6e14ae7da6a6ea265178ff71286ff903aec74adee98f660bb0e4ca12 \
    >> "$OUT/vampi.up.log" 2>&1 || return 1
  wait_ready vampi "http://vampi-unsafe:5000/" 20 10 || return 1
  wait_ready vampi-safe "http://vampi-safe:5000/" 10 10
  return $?
}

up_xvwa() {
  local commit; commit=$(pinned_commit xvwa)
  log "xvwa: clone @${commit:0:12}… + own LAMP pair"
  rm -rf /tmp/xvwa
  git clone --quiet https://github.com/s4n7h0/xvwa.git /tmp/xvwa || return 1
  git -C /tmp/xvwa checkout --quiet "$commit" || return 1
  # config.php points at localhost; patch to the db service name
  sed -i 's/$host = "localhost";/$host = "xvwa-db";/' /tmp/xvwa/config.php || return 1
  docker run -d --name xvwa-db --network phasec-iso \
    -e MYSQL_ROOT_PASSWORD= -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_DATABASE=xvwa \
    mysql:5.7 > "$OUT/xvwa.up.log" 2>&1 || return 1
  docker run -d --name xvwa --network phasec-iso \
    -v /tmp/xvwa:/var/www/html php:8.1-apache \
    bash -c "docker-php-ext-install mysqli >/dev/null 2>&1; apache2-foreground" \
    >> "$OUT/xvwa.up.log" 2>&1 || return 1
  # step-zero proof: the web tier serves the app; DB init via /setup/ is
  # step-1 work, not step-zero.
  wait_ready xvwa "http://xvwa:80/" 20 10
  return $?
}

up_wackopicko() {
  log "wackopicko: official image (digest-pinned in seal)"
  docker run -d --name wackopicko --network phasec-iso \
    adamdoupe/wackopicko@sha256:76d1a9ad02ad7fb6bbc000eb12956f457087a0f5883bd23b6cc49d3051feae02 \
    > "$OUT/wackopicko.up.log" 2>&1 || return 1
  wait_ready wackopicko "http://wackopicko:80/" 20 10
  return $?
}

main() {
  ensure_net
  local wanted="${*:-shepherd railsgoat vampi xvwa wackopicko}"
  local overall=0 name rc
  : > "$OUT/summary.txt"
  for name in $wanted; do
    case "$name" in
      shepherd)    up_shepherd ;;
      railsgoat)   up_railsgoat ;;
      vampi)       up_vampi ;;
      xvwa)        up_xvwa ;;
      wackopicko)  up_wackopicko ;;
      *) log "unknown candidate: $name"; continue ;;
    esac
    rc=$?
    if [ $rc -eq 0 ]; then
      log "READY: $name (probe HTTP $(cat "$OUT/$name.probe" 2>/dev/null))"
      echo "READY $name" >> "$OUT/summary.txt"
    else
      record_blocked "$name" "$rc" "probe or compose failed — see $name.up.log"
      echo "BLOCKED $name" >> "$OUT/summary.txt"
      overall=1
    fi
  done
  log "=== summary ==="
  cat "$OUT/summary.txt"
  # step-zero is a proof, not a deployment: clean everything up.
  docker ps -aq --filter "network=phasec-iso" | xargs -r docker rm -f >/dev/null 2>&1
  docker network rm phasec-iso >/dev/null 2>&1
  exit $overall
}

main "$@"
