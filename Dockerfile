FROM golang:1.13.11-alpine3.10 AS build-env

RUN apk add --no-cache --upgrade git openssh-client ca-certificates
RUN go get -u github.com/golang/dep/cmd/dep
WORKDIR /go/src/app

# Install
RUN GO111MODULE=on go get -u github.com/projectdiscovery/nuclei/v2/cmd/nuclei

ENTRYPOINT ["nuclei"]