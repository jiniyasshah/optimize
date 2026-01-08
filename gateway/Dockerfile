# Use a specific Go runtime version as a parent image
FROM golang:1.22-alpine

# Set the current working directory inside the container
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies (already handled by go.mod and go.sum)
RUN go mod download || true

# Copy the rest of the code
COPY . .

# Build the Go binary
RUN go build -o main ./cmd/server/main.go

# Expose the port the app runs on
EXPOSE 8080

# Run the Go binary
CMD ["./main"]
