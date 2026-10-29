# ---- 构建阶段 ----
FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install ".[console]"

# ---- 运行阶段 ----
FROM python:3.12-slim
LABEL org.opencontainers.image.title="p2s" \
      org.opencontainers.image.description="php2shell 检测控制台 (CVE-2026-109618 / CVE-2026-109619)" \
      org.opencontainers.image.source="https://example.internal/p2s"

RUN useradd -r -u 10001 -m -d /app p2s && \
    mkdir -p /app/data && chown -R p2s:p2s /app
WORKDIR /app

COPY --from=builder /install /usr/local
COPY src/p2s /app/src/p2s
COPY scripts /app/scripts
COPY examples /app/examples

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    P2S_DATA_DIR=/app/data \
    PYTHONPATH=/app/src

USER p2s
EXPOSE 8080
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx,sys;sys.exit(0 if httpx.get('http://127.0.0.1:8080/api/health',timeout=4).status_code==200 else 1)"

CMD ["python", "-m", "uvicorn", "p2s.console.app:app", "--host", "0.0.0.0", "--port", "8080"]