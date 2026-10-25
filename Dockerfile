FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /7guard ./cmd/7guard

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /7guard /usr/local/bin/7guard
COPY rules/ /app/rules/
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["7guard"]
CMD ["--profile=lite", "--mode=detect", "--listen=:8080", "--upstream=http://backend:9090", "--rules-dir=/app/rules"]
