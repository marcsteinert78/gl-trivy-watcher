# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates git

# Copy all source files
COPY go.mod *.go ./

# Download and verify dependencies
RUN go mod tidy && go mod download

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /trivy-watcher .

# Final stage - minimal image
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /trivy-watcher /trivy-watcher

# Run as non-root
USER 65534:65534

ENTRYPOINT ["/trivy-watcher"]
