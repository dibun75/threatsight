# Docker Host Rules

ThreatSight runs on a shared Docker host. Never assume a preferred host port is free.

## Rules

1. Before `docker compose up`, inspect host port usage and choose a free host port when the preferred port is occupied.
2. Prefer configurable host-port environment variables over hard-coded ports.
3. Never stop, remove, or modify containers belonging to other projects.
4. Never run broad destructive commands such as `docker system prune -a --volumes` on the shared host.
5. Remove only exact, reviewed ThreatSight resources identified by Compose labels and explicit allow-lists when cleanup is authorized.
6. Preserve named database volumes unless the task explicitly requires a fresh database.
7. The current Compose project name is `threatsight`; current containers have explicit names and `com.threatsight.generation=current`.
8. Document the actual host ports in the local deployment instructions when they differ from defaults.
9. Before cleanup, inspect `docker ps -a`, `docker images`, `docker volume ls`, and `docker network ls` and verify ownership/project labels where available.
10. After startup, verify health endpoints and `docker compose ps`.

## Cleanup policy

"Clean old containers/images/volumes" means **the exact reviewed ThreatSight manifest only**, never the shared Docker host globally.

If ownership is ambiguous, do not delete the resource; report it instead.
