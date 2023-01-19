FROM golang:1.19.5-alpine as build-env
RUN apk add build-base
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

FROM alpine:3.17.1
RUN apk add --no-cache bind-tools ca-certificates chromium curl
COPY --from=build-env /go/bin/nuclei /usr/local/bin/nuclei
HEALTHCHECK --interval=5m --timeout=3s \
  CMD curl -f http://127.0.0.1:63636/metrics || exit 1
ENTRYPOINT ["nuclei"]
