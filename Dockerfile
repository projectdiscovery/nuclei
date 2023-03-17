# Build
FROM golang:1.20.1-alpine AS build-env
RUN apk add build-base
WORKDIR /app
COPY . /app
WORKDIR /app/v2
RUN go mod download
RUN go build ./cmd/nuclei

# Release
FROM alpine:3.17.2
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools chromium ca-certificates
COPY --from=build-env /app/v2/nuclei /usr/local/bin/
HEALTHCHECK --interval=5m --timeout=3s \
  CMD curl -f http://127.0.0.1:63636/metrics || exit 1

ENTRYPOINT ["nuclei"]
