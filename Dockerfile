FROM node:24-slim AS web-build

WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/index.html web/tsconfig.json web/tsconfig.app.json web/tsconfig.node.json web/vite.config.ts ./
COPY web/src ./src
RUN npm run build

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SNE_SEC_CELO_DATABASE=/data/reviews.sqlite3 \
    SNE_SEC_CELO_WEB_ROOT=/app/web

RUN apt-get update \
    && apt-get install --yes --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system sne-sec \
    && useradd --system --gid sne-sec --home /app sne-sec
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
COPY --from=web-build /web/dist /app/web

COPY docker-entrypoint.sh /usr/local/bin/sne-sec-celo-entrypoint
RUN chmod 0755 /usr/local/bin/sne-sec-celo-entrypoint \
    && mkdir /data \
    && chown sne-sec:sne-sec /data
EXPOSE 8000

ENTRYPOINT ["sne-sec-celo-entrypoint"]
CMD ["uvicorn", "sne_sec_celo.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
