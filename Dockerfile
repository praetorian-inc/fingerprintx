FROM golang:alpine AS builder
# Set the Current Working Directory inside the container
WORKDIR /app/fingerprint
# We want to populate the module cache based on the go.{mod,sum} files.
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN go build -o /out/fingerprintx ./cmd/fingerprintx

FROM alpine:latest
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /out/fingerprintx /usr/local/bin/

ENTRYPOINT ["fingerprintx"]
