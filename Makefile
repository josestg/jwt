GO ?= go

test:
	$(GO) test -race -coverprofile=coverage.out -timeout 30s -v ./...