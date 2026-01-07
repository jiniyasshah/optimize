# Stage 1: Builder
FROM golang:1.25.4-alpine

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy dependency files first (better caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary (statically linked)
RUN CGO_ENABLED=0 GOOS=linux go build -o waf-server ./cmd/server/main.go


FROM alpine:latest

WORKDIR /root/

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy the binary from builder
COPY --from=builder /app/waf-server .

# Copy static assets (HTML pages)
COPY --from=builder /app/pages ./pages

# Create directory for AutoCert cache
RUN mkdir -p certs

# Expose HTTP and HTTPS ports
EXPOSE 80 443

# Run the binary
CMD ["./waf-server"]