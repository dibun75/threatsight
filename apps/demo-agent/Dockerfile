FROM python:3.12-slim

WORKDIR /app

RUN useradd --create-home --uid 10001 threatsight

COPY pyproject.toml /app/pyproject.toml
COPY src /app/src

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . \
    && pip uninstall --yes pip setuptools wheel \
    && rm -rf /root/.cache \
    && chown -R threatsight:threatsight /app

USER threatsight

EXPOSE 8090

CMD ["uvicorn", "demo_agent.main:app", "--host", "0.0.0.0", "--port", "8090"]
