FROM golang:1.20-alpine AS builder
RUN mkdir /src
ADD . /src
WORKDIR /src

RUN go env -w GO111MODULE=auto
RUN go build -o main .

FROM ubuntu:22.04

WORKDIR /

COPY --from=builder /src/main /main
EXPOSE 8190
ENTRYPOINT ["/main"]