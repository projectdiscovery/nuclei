# Build
FROM golang:1.21-alpine AS build-env
RUN apk add build-base
WORKDIR /app
COPY . /app
WORKDIR /app
RUN go mod download
RUN go build ./cmd/nuclei

# Release
FROM alpine:3.18.6
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools chromium ca-certificates
COPY --from=build-env /app/nuclei /usr/local/bin/

ENTRYPOINT ["nuclei"]