GO_CMD?=go
BINNAME=labs-validator
GOPATH?=$$($(GO_CMD) env GOPATH)
GOFMT_FILES?=$$(find . -name '*.go')

default: help

dev: ## Build and copy to GOPATH/bin
	$(GO_CMD) build -o ${BINNAME} ./cmd/labs-validator

image: ## Build local docker image
	@docker build -t $(BINNAME):latest .

help: ## Output make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: help dev

