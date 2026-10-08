.PHONY: run run-worker readiness build vet test tidy migrate-up migrate-down sqlc

# Local dev (in-memory BETA — no database required)
run:
	go run ./cmd/api

run-worker:
	go run ./cmd/worker

readiness:
	go run ./cmd/readiness

build:
	go build -o bin/api ./cmd/api
	go build -o bin/worker ./cmd/worker

vet:
	go vet ./...

test:
	go test ./...

tidy:
	go mod tidy

# Goose migrations (requires goose + RTM_DATABASE_URL)
#   go install github.com/pressly/goose/v3/cmd/goose@latest
migrate-up:
	goose -dir migrations postgres "$$RTM_DATABASE_URL" up

migrate-down:
	goose -dir migrations postgres "$$RTM_DATABASE_URL" down

# Generate typed queries (requires sqlc)
#   go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
sqlc:
	sqlc generate
