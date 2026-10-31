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
      org.opencontainers.image.version="0.23.0" \
      org.opencontainers.image.description="php2shell 检测控制台 (CVE-2026-109618 / CVE-2026-109619)"

RUN useradd -r -u 10001 -m -d /app p2s && \
    mkdir -p /app/data && chown -R p2s:p2s /app
WORKDIR /app

# 包只装一次（构建阶段 --prefix 到 /install），运行阶段不再额外 COPY src，
# 否则 sys.path 上会出现两份同名的 p2s，改哪份生效取决于解释器路径。
COPY --from=builder /install /usr/local
COPY scripts /app/scripts
COPY examples /app/examples

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    P2S_DATA_DIR=/app/data

USER p2s
EXPOSE 18080
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx,sys;sys.exit(0 if httpx.get('http://127.0.0.1:18080/api/health',timeout=4).status_code==200 else 1)"

# 容器内必须监听 0.0.0.0 才能被 publish 出来；对外暴露范围由 compose 的
# 端口映射决定（默认 127.0.0.1）与 P2S_CONSOLE_PASSWORD 共同控制。
CMD ["python", "-m", "uvicorn", "p2s.console.app:app", "--host", "0.0.0.0", "--port", "18080"]
