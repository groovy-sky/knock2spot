FROM golang:1.21-alpine3.18 AS builder
RUN apk add --no-cache git && go install github.com/groovy-sky/knock2spot@v1.1.2

FROM alpine:3.18
COPY --from=builder /go/bin/knock2spot /main
CMD ["/main"]