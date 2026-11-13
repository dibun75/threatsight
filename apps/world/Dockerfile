FROM python:3.12-slim

WORKDIR /app
RUN useradd --create-home --uid 10002 world

COPY pyproject.toml README.md LICENSE NOTICE /app/
COPY src /app/src
RUN pip install --no-cache-dir . && mkdir -p /runs && chown world:world /runs

USER world
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["threatsight-world"]
