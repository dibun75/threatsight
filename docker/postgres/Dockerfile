FROM postgres:16-alpine

# The upstream image's gosu binary was built with a vulnerable Go standard
# library. Alpine's su-exec provides the same one-shot privilege drop without
# retaining that binary in the runtime image.
RUN apk add --no-cache su-exec \
    && sed -i 's/exec gosu postgres/exec su-exec postgres/' /usr/local/bin/docker-entrypoint.sh \
    && rm -f /usr/local/bin/gosu
