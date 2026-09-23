# STAGE 1
FROM golang:1.26-alpine as builder

WORKDIR /app

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code into container
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN go build -o bassword-server ./cmd/bassword-server/main.go

# RUNNER
FROM scratch
WORKDIR /app
COPY --from=builder /app/bassword-server .
EXPOSE 8080

# Run application
CMD ["./bassword-server"]
