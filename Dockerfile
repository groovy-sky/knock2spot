FROM docker.io/library/golang:1.24-alpine3.20 AS builder
WORKDIR /src
COPY . .
RUN apk add --no-cache git && go build -o /go/bin/knock2spot .

FROM docker.io/library/alpine:3.20
ENV HTTP_PORT=8080
EXPOSE ${HTTP_PORT}/tcp
COPY --from=builder /go/bin/knock2spot /main
RUN apk add --no-cache ca-certificates && update-ca-certificates && mkdir -p /etc/pki/ca-trust/source && ln -s /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors
CMD ["/main"]