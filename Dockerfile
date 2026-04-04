# Stage 1: Build frontend
FROM node:20-alpine AS frontend
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci --silent
COPY web/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.24-alpine AS backend
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/web/build web/build
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=docker" -o mythnet ./cmd/mythnet

# Stage 3: Minimal runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -h /data mythnet

COPY --from=backend /app/mythnet /usr/local/bin/mythnet
COPY config.example.yaml /etc/mythnet/config.yaml

USER mythnet
WORKDIR /data

EXPOSE 8080 1162/udp 1514/udp 7946 7947

ENTRYPOINT ["mythnet"]
CMD ["-c", "/etc/mythnet/config.yaml"]
