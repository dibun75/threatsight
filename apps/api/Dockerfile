FROM python:3.12-slim

WORKDIR /app

RUN useradd --create-home --uid 10001 threatsight

COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
COPY alembic.ini /app/alembic.ini
COPY alembic /app/alembic

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .[dev] \
    && pip uninstall --yes pip setuptools wheel \
    && rm -rf /root/.cache \
    && chown -R threatsight:threatsight /app

USER threatsight

EXPOSE 8000

CMD ["uvicorn", "threatsight_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
