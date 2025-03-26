# Build
FROM golang:1.22-alpine AS builder

RUN apk add build-base
WORKDIR /app
COPY . /app
RUN make verify
RUN make build

# Release
FROM alpine:latest

RUN apk add --no-cache bind-tools chromium ca-certificates
COPY --from=builder /app/bin/nuclei /usr/local/bin/

ENTRYPOINT ["nuclei"]