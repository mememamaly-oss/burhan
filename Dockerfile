FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BURHAN_OWNER_GATE=/var/lib/burhan/owner-gate.json

WORKDIR /opt/burhan
COPY pyproject.toml README.md LICENSE ./
COPY burhan ./burhan

RUN python -m pip install --no-cache-dir . \
    && mkdir -p /var/lib/burhan \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin burhan \
    && chown -R burhan:burhan /opt/burhan /var/lib/burhan

USER burhan
ENTRYPOINT ["burhan"]
