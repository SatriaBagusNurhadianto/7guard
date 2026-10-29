.PHONY: build test lint vet release-dry

build:
	go build ./...

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

release-dry:
	goreleaser release --snapshot --clean