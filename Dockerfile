# Stage 1: Build static Go binary
FROM golang:1.24.3 AS builder

# Set the working directory inside the builder container
WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker's build cache.
# This ensures that 'go mod download' is only re-run if dependencies change.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build a statically linked Go binary.
# CGO_ENABLED=0: Disables CGO, ensuring the binary does not link against system C libraries.
# GOOS=linux GOARCH=amd64: Compiles for Linux AMD64 architecture, standard for Docker.
# -a: Forces rebuilding of packages to ensure all dependencies are included statically.
# -o snmp-trap-sender: Specifies the output executable name.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o snmp-trap-sender .

# Stage 2: Create a minimal production image
# FROM scratch: This uses the absolute smallest base image, containing nothing but the kernel.
#               Possible because the Go binary is statically compiled.
FROM scratch

# Set the working directory inside the final container
WORKDIR /app

# Copy the statically compiled binary from the 'builder' stage into the current image.
COPY --from=builder /app/snmp-trap-sender .

# IMPORTANT: For production, do NOT copy sensitive files like credentials.json directly into the image.
# Instead, manage them securely using:
# - Docker Secrets (Docker Swarm)
# - Kubernetes Secrets (Kubernetes)
# - Environment variables (for non-sensitive configs)
# - Mounting as a volume at runtime (e.g., -v /host/path/credentials.json:/app/credentials.json)
#
# FOR TESTING/DEVELOPMENT, we uncomment this line to include credentials.json in the image.
COPY --from=builder /app/credentials.json .


# Inform Docker that the container listens on port 8080.
# This is metadata; actual port publishing requires '-p 8080:8080' when running.
EXPOSE 8080

# Define the command that will be executed when the container starts.
# Use ENTRYPOINT with JSON array format for direct execution without a shell.
ENTRYPOINT ["./snmp-trap-sender"]