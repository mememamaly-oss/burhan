# r19-3 (order 2026-11-16, item 1c): production image, non-root user.
# Design constraints:
#   - pipx-style clean install of the wheel (not a source mount)
#   - dedicated unprivileged user with a writable HOME for the gate store
#     and scan outputs; NOTHING runs as root
#   - the CLI's authorization registry ships read-only (root-owned) — the
#     runtime user cannot weaken the scan policy
#   - chromium/playwright are OUT of this image (the browser engine is an
#     optional surface: burhan degrades loudly with --no-browser and the
#     capability matrix records it); a separate -browser tag may add it
FROM python:3.12-slim AS base

# tini: proper signal forwarding for SIGINT unwinding (R15-4 doctrine)
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

# non-root user, fixed uid/gid for predictable volume permissions
RUN groupadd -r -g 10001 burhan \
    && useradd -r -u 10001 -g burhan -m -d /home/burhan -s /usr/sbin/nologin burhan

WORKDIR /home/burhan

# build the wheel in a builder stage so compilers/toolchains stay out
FROM base AS builder
WORKDIR /src
COPY . .
RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir /dist

FROM base AS runtime
COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# the authorization registry: root-owned, read-only for the runtime user
COPY --chown=root:root authorized-targets.json /opt/burhan/authorized-targets.json
RUN chmod 0444 /opt/burhan/authorized-targets.json
# Runtime state/output is writable by the fixed non-root UID, including mounted CI volumes.
RUN install -d -o 10001 -g 10001 -m 0750 /var/lib/burhan
ENV BURHAN_AUTHORIZED_TARGETS=/opt/burhan/authorized-targets.json
ENV BURHAN_DATA_DIR=/var/lib/burhan

USER burhan
ENTRYPOINT ["/usr/bin/tini", "--", "burhan"]
CMD ["--help"]
