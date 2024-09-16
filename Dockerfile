FROM golang:1.21-alpine

WORKDIR /usr/src/nuclei

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . ./
RUN apk add build-base bind-tools chromium ca-certificates
RUN go build -v -ldflags '-extldflags "-static"' \
    -o /usr/local/bin/nuclei ./cmd/nuclei/main.go

CMD ["nuclei"]