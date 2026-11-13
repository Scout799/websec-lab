FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    WEBSEC_PROJECT_ROOT=/app WEBSEC_GATEWAY_BIND=0.0.0.0 \
    WEBSEC_CHROME_PATH=/usr/bin/chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx openssl chromium libnss3-tools fonts-noto-cjk ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 lab
WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r requirements.lock
COPY . /app
RUN pip install --no-deps --no-build-isolation . \
    && mkdir -p /app/artifacts /app/.websec-local \
    && chown -R lab:lab /app
USER lab
EXPOSE 8443
HEALTHCHECK --interval=15s --timeout=20s --start-period=90s \
    CMD ["python", "scripts/container_healthcheck.py"]
ENTRYPOINT ["python", "-m", "websec_lab.container_entry"]
