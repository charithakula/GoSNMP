# Use the official Golang image to build the app
FROM golang:1.20 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code
COPY . .

# Build the Go app
RUN go build -o snmp-trap-sender

# Use a smaller base image to run the app
FROM debian:bullseye-slim

# Install SNMP utils (optional but useful for debugging/trap viewing)
RUN apt-get update && apt-get install -y snmp && apt-get clean

# Set the working directory
WORKDIR /app

# Copy the binary and credentials
COPY --from=builder /app/snmp-trap-sender .
COPY credentials.json .

# Expose the port used by the service
EXPOSE 8080

# Set the entry point
CMD ["./snmp-trap-sender"]
