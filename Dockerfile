# Stage 1: download kubeseal binary
FROM alpine:3.21 AS kubeseal-downloader
ARG KUBESEAL_VERSION=0.38.4
RUN apk add --no-cache curl tar && \
    curl -fsSL "https://github.com/bitnami/sealed-secrets/releases/download/v${KUBESEAL_VERSION}/kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz" \
      -o /tmp/kubeseal.tar.gz && \
    tar -xzf /tmp/kubeseal.tar.gz -C /tmp kubeseal && \
    chmod +x /tmp/kubeseal

# Stage 2: runtime
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=kubeseal-downloader /tmp/kubeseal /usr/local/bin/kubeseal

COPY main.py .
COPY templates/ templates/

ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
