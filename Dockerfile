FROM golang:1.26
WORKDIR /app

# Dependencies
COPY go.mod go.sum ./
RUN go mod download

# Source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN go build -o bassword-server ./cmd/bassword-server/main.go

# ENV and ports
EXPOSE 8080

CMD ["./bassword-server"]
