FROM golang:1.17.1-alpine as build-env
RUN GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei

FROM alpine:3.14
RUN apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /go/bin/nuclei /usr/local/bin/nuclei
ENTRYPOINT ["nuclei"]
