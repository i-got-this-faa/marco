.PHONY: build test lint clean docker run

build:
	go build -o bin/marco ./cmd/marco

test:
	go test -race ./pkg/...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

clean:
	rm -rf bin/

docker:
	docker build -t marco:latest .
	docker compose build

run:
	go run ./cmd/marco
