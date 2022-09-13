.PHONY: lint
lint:
	go vet && golangci-lint run ./...

.PHONY: test
test: lint
	go test -race -v ./...
