FROM golang:1.21-alpine3.18 AS builder
RUN apk add --no-cache git && go install github.com/groovy-sky/knock2spot@v1.1.7

FROM alpine:3.18
ENV HTTP_PORT=8080
EXPOSE ${HTTP_PORT}/tcp
COPY --from=builder /go/bin/knock2spot /main
RUN apk add --no-cache ca-certificates && update-ca-certificates && mkdir -p /etc/pki/ca-trust/source && ln -s /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors
CMD ["/main"]