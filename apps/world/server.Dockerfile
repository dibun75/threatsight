# Demo-world HTTP service for the web UI. Synthetic data only, no database.
# (apps/world/Dockerfile is the CLI/benchmark image; this one runs the long-lived server.)
FROM python:3.12-slim

WORKDIR /app
RUN useradd --create-home --uid 10002 world

COPY pyproject.toml README.md LICENSE NOTICE /app/
COPY src /app/src
COPY recordings /app/recordings
RUN pip install --no-cache-dir . && mkdir -p /runs && chown world:world /runs

USER world
ENV THREATSIGHT_WORLD_HOST=0.0.0.0 \
    THREATSIGHT_WORLD_PORT=8092 \
    THREATSIGHT_WORLD_RUNS_DIR=/runs \
    THREATSIGHT_WORLD_RECORDINGS=/app/recordings
EXPOSE 8092
CMD ["python", "-m", "threatsight_world.server"]
