GO_LINES_IGNORED_DIRS=tests_vectors word_lists
GO_PACKAGES=./curve/... ./keystore/... ./mnemonic/...
GO_FOLDERS=$(shell echo ${GO_PACKAGES} | sed -e "s/\.\///g" | sed -e "s/\/\.\.\.//g")


.PHONY: fmt
fmt:
	go fmt ./...
	make format-lines

.PHONY: format-lines
format-lines: ## formats all go files with golines
	go install github.com/segmentio/golines@latest
	golines -w -m 120 --ignore-generated --shorten-comments --ignored-dirs=${GO_LINES_IGNORED_DIRS} ${GO_FOLDERS}

.PHONY: tests
tests:
	go test -v ./...

.PHONY: build
build:
	go build -v ./...