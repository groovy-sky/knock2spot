FROM golang:1.21-alpine3.18 AS builder
RUN apk add --no-cache git && go install github.com/groovy-sky/knock2spot@v1.1.5

FROM alpine:3.18
ENV HTTP_PORT=8080
EXPOSE ${HTTP_PORT}/tcp
COPY --from=builder /go/bin/knock2spot /main
CMD ["/main"]