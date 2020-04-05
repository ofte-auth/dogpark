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

build-containers:
	docker build -t services-deploy:latest deploy
	GOOS=linux go build -ldflags="${LD_FLAGS}" -o ./cmd/migration/builds/migrate-linux ./cmd/migration/main.go
	GOOS=linux go build -ldflags="${LD_FLAGS}" -o ./cmd/auth-service/builds/auth-service-linux ./cmd/auth-service/main.go
	GOOS=linux go build -ldflags="${LD_FLAGS}" -o ./cmd/admin-service/builds/admin-service-linux ./cmd/admin-service/main.go
	@echo --- If next commands fail, execute: docker login registry.gitlab.com
	@echo --- Enter your username and password/personal access token for gitlab to access the docker registry
	docker build cmd/migration -t registry.gitlab.com/ofte/docker-registry/ofte-migrate-cmd:latest
	docker build cmd/auth-service -t registry.gitlab.com/ofte/docker-registry/ofte-auth-service:latest
	docker build cmd/admin-service -t registry.gitlab.com/ofte/docker-registry/ofte-admin-service:latest

deploy:
	@echo --- If next commands fail, execute: docker login registry.gitlab.com
	@echo --- Enter your username and password/personal access token for gitlab to access the docker registry
	docker push registry.gitlab.com/ofte/docker-registry/ofte-migrate-cmd:latest
	docker push registry.gitlab.com/ofte/docker-registry/ofte-auth-service:latest
	docker push registry.gitlab.com/ofte/docker-registry/ofte-admin-service:latest

.PHONY: lint test test-verbose build-containers deploy
