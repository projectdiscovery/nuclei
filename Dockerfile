# Build
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder

RUN apk add build-base
WORKDIR /app
COPY . /app
RUN make verify
RUN make build

# Release
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache bind-tools chromium ca-certificates \
    && addgroup -S nuclei \
    && adduser -S -D -h /home/nuclei -G nuclei nuclei
COPY --from=builder /app/bin/nuclei /usr/local/bin/

USER nuclei
WORKDIR /home/nuclei

ENTRYPOINT ["nuclei"]
