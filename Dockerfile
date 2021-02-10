#
# Dockerfile for chinadns-ng
#

#
# Build stage
#
FROM alpine AS builder

# copy source
COPY . /tmp/chinadns-ng

# build
RUN apk update \
  && apk add --no-cache --virtual .build-deps build-base linux-headers \
  && cd /tmp/chinadns-ng \
  && make -j$(nproc) CFLAGS="-O3 -pipe" \
  && make install DESTDIR="/app" \
  && make clean \
  && cd / \
  && rm -r /tmp/chinadns-ng \
  && apk del .build-deps \
  && rm -rf /var/cache/apk/*

#
# Runtime stage
#
FROM alpine

COPY --from=builder /app/chinadns-ng /app/chinadns-ng

USER nobody
ENTRYPOINT ["/app/chinadns-ng"]
