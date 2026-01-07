# Stage 1: Builder
# We use the version you specified
FROM golang:1.25.4-alpine AS builder

WORKDIR /app

# Install git (sometimes needed for go mod)
RUN apk add --no-cache git

# Copy dependency files first (Better Docker Caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application
COPY . .

# Build the binary (Statically linked for Alpine)
RUN CGO_ENABLED=0 GOOS=linux go build -o waf-server ./cmd/server/main.go

# Stage 2: Runner (Tiny Image)
FROM alpine:latest

WORKDIR /root/

# Install Certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy the binary from the builder stage
COPY --from=builder /app/waf-server .

# Copy your HTML pages (404, 502)
COPY --from=builder /app/pages ./pages

# Create certs directory for AutoCert
RUN mkdir -p certs

# Expose standard web ports
EXPOSE 80 443

# Run the binary
CMD ["./waf-server"]