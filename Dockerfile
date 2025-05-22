# Stage 1: Build static Go binary
FROM golang:1.24.3 AS builder

WORKDIR /app

# Copy go.mod and go.sum first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the application code
COPY . .

# Build a static binary (CGO disabled)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o snmp-trap-sender .

# Stage 2: Create minimal image using scratch
FROM scratch

# Set working directory
WORKDIR /app

# Copy statically compiled binary and required files
COPY --from=builder /app/snmp-trap-sender .
COPY --from=builder /app/credentials.json .

# Expose the port used by the HTTP server
EXPOSE 8080

# Run the Go binary
ENTRYPOINT ["./snmp-trap-sender"]
