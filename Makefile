#########
# BUILD #
#########

.PHONY: fmt
fmt: ## Run go fmt
	@echo Go fmt... >&2
	@go fmt ./...

.PHONY: vet
vet: ## Run go vet
	@echo Go vet... >&2
	@go vet ./...

.PHONY: go-mod-tidy
go-mod-tidy: ## Run go mod tidy
go-mod-tidy:
	@echo Run go mod tidy... >&2
	@go mod tidy

########
# TEST #
########

.PHONY: tests
tests: ## Run tests
tests: fmt
tests: vet
	@echo Running tests... >&2
	@go test ./... -race -coverprofile=coverage.out -covermode=atomic
	@go tool cover -html=coverage.out

########
# HELP #
########

.PHONY: help
help: ## Shows the available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-40s\033[0m %s\n", $$1, $$2}'
