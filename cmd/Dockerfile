FROM golang:1.21.4 AS builder
WORKDIR /app
COPY go.* ./
COPY main.go ./
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o main

FROM scratch
COPY --from=builder /app/main /main
CMD ["/main"]