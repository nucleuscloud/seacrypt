GO=go

default: all

all: build test
.PHONY: all

lint:
	golangci-lint run
.PHONY: lint

build:
	$(GO) build -o bin/seacrypt cmd/*.go
.PHONY: build

build-release:
	env GOOS=darwin GOARCH=amd64 $(GO) build -o bin/seacrypt_darwin_amd64 cmd/*.go
	env GOOS=darwin GOARCH=arm64 $(GO) build -o bin/seacrypt_darwin_arm64 cmd/*.go
	env GOOS=linux GOARCH=amd64 $(GO) build -o bin/seacrypt_linux_amd64 cmd/*.go
	env GOOS=linux GOARCH=arm64 $(GO) build -o bin/seacrypt_linux_arm64 cmd/*.go
	sha256sum bin/* >> bin/SHA256SUMS
.PHONY: build-release

test:
	$(GO) test ./... -race -v
.PHONY: test

help:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$'
.PHONY: help
