FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SNE_SEC_CELO_DATABASE=/data/reviews.sqlite3

RUN groupadd --system sne-sec && useradd --system --gid sne-sec --home /app sne-sec
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN mkdir /data && chown sne-sec:sne-sec /data
USER sne-sec
EXPOSE 8000

CMD ["uvicorn", "sne_sec_celo.api:app", "--host", "0.0.0.0", "--port", "8000"]
