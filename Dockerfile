FROM golang:alpine as builder

RUN mkdir -p /app
WORKDIR /app
COPY ./go.mod .
RUN go mod download

COPY . .
RUN cd ./cmd/nuclei && go build -o nuclei .

FROM alpine

RUN mkdir /app
RUN adduser -S -D -H -h /app appuser
USER appuser
COPY --from=builder /app/cmd/nuclei/nuclei /app

WORKDIR /app
CMD ["./nuclei"]
