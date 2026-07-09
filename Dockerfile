# Build stage runs on the native build platform and cross-compiles for the
# target platform, so multi-platform builds need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Cross-compile a static binary for the target platform
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o webhook ./cmd/webhook

FROM gcr.io/distroless/static-debian12:nonroot@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/webhook /app/

# Expose the webhook port
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["/app/webhook"]
