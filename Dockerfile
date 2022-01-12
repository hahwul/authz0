# BUILDER
FROM golang:latest AS builder
WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go build -o authz0

# RUNNING
FROM debian:buster
RUN mkdir /app
COPY --from=builder /go/src/app/authz0 /app/authz0
WORKDIR /app/
CMD ["/app/authz0"]