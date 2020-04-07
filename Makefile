lint:
	golangci-lint run || true

test:
	go test ./...

test-verbose:
	go test -v ./...

version=v0.9.0

LD_FLAGS = -X 'github.com/ofte-auth/dogpark/internal.commit=$(shell git rev-parse HEAD)' \
	-X 'github.com/ofte-auth/dogpark/internal.buildDate=$(shell date)' \
	-X 'github.com/ofte-auth/dogpark/internal.version=$(version)'

gosec:
	gosec ./...

build-containers:
	docker build -t services-deploy:latest deploy
	GOOS=linux go build -ldflags="${LD_FLAGS}" -o ./cmd/migration/builds/migrate-linux ./cmd/migration/main.go
	GOOS=linux go build -ldflags="${LD_FLAGS}" -o ./cmd/auth-service/builds/auth-service-linux ./cmd/auth-service/main.go
	GOOS=linux go build -ldflags="${LD_FLAGS}" -o ./cmd/admin-service/builds/admin-service-linux ./cmd/admin-service/main.go
	docker build cmd/migration -t dogpark-migrate-cmd:latest
	docker build cmd/auth-service -t dogpark-auth-service:latest
	docker build cmd/admin-service -t dogpark-admin-service:latest

.PHONY: lint test test-verbose gosec build-containers
