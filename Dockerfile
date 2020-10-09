FROM golang:alpine as builder

RUN mkdir -p /app
WORKDIR /app
COPY ./v2/go.mod .
RUN go mod download

COPY . .
RUN cd ./v2/cmd/nuclei && go build -o nuclei .

FROM alpine

RUN mkdir /app
RUN adduser --home /app --shell /bin/sh --disabled-password appuser
COPY --from=builder /app/v2/cmd/nuclei/nuclei /app
USER appuser

WORKDIR /app
ENTRYPOINT ["/app/nuclei"]
