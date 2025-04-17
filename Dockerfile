FROM golang:1.19-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the binaries
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/bbs-bench ./cmd/bench
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/bbs-credgen ./cmd/credgen
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/bbs-server ./wasm/server.go
RUN GOOS=js GOARCH=wasm go build -o /bin/main.wasm ./wasm/main.go
RUN cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" /bin/

# Create smaller final image
FROM alpine:latest

# Install necessary tools
RUN apk --no-cache add ca-certificates

# Copy the binaries from the builder stage
COPY --from=builder /bin/bbs-bench /bin/bbs-credgen /bin/bbs-server /bin/
COPY --from=builder /bin/main.wasm /bin/wasm_exec.js /wasm/

# Create necessary directories
RUN mkdir -p /wasm /data

# Set the working directory
WORKDIR /data

# Expose port for WASM demo server
EXPOSE 8080

# Default command
CMD ["echo", "Use 'bbs-bench', 'bbs-credgen', or 'bbs-server' commands"]