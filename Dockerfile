#
# Dockerfile for chinadns-ng
#

FROM alpine

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

USER nobody
ENTRYPOINT ["/app/chinadns-ng"]
