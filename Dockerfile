FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o webhook ./cmd/webhook

# Create a minimal production image
FROM alpine:3.19

# Install CA certificates for HTTPS requests
RUN apk --no-cache add ca-certificates && \
    update-ca-certificates

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/webhook /app/

# Use the non-root user
USER appuser

# Expose the webhook port
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["/app/webhook"]
