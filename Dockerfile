FROM golang:1.13.10-alpine3.11
RUN mkdir /nuclei
ADD . /nuclei
WORKDIR /nuclei
RUN go build -o nuclei /nuclei/cmd/nuclei/main.go
ENTRYPOINT ["/nuclei/nuclei"]