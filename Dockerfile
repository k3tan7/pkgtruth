FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PKGTRUTH_DATA_DIR=/data
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && groupadd --gid 10001 pkgtruth && useradd --uid 10001 --gid 10001 --no-create-home pkgtruth && mkdir /data && chown 10001:10001 /data
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"
CMD ["pkgtruth", "serve", "--port", "8000"]
