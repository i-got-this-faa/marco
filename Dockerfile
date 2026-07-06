FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags '-s -w' -o /marco ./cmd/marco

FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /marco /usr/local/bin/marco

EXPOSE 25 587 465 143 993 80 443 8080

ENTRYPOINT ["marco"]
CMD ["run"]
