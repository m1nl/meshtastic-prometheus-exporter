FROM python:3.13-slim AS builder

RUN mkdir -p /app

WORKDIR /app

COPY pyproject.toml /app
COPY README.md /app
COPY src /app/src

RUN pip wheel .

FROM python:3.13-slim

RUN mkdir -p /app

WORKDIR /app

COPY --from=builder /app/meshtastic_prometheus_exporter*.whl /app

RUN pip install --no-cache-dir /app/meshtastic_prometheus_exporter*.whl

ENTRYPOINT ["meshtastic-prometheus-exporter"]
