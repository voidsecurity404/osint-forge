# osint-forge — build & test
#
# NOTE: the Wails GUI needs the webkit2gtk-4.1 dev libraries and is built with
# the `webkit2_41` build tag. The headless CLI (reconcli) and all library
# packages build with a plain Go toolchain and no system deps.

GO ?= go
TAGS ?= webkit2_41

.PHONY: all test vet build cli gui run clean fmt tidy

all: test vet build

## test: run the unit tests
test:
	$(GO) test ./internal/...

## vet: static analysis of library + CLI packages
vet:
	$(GO) vet ./internal/... ./cmd/...

## fmt: format all Go sources
fmt:
	$(GO) fmt ./...

## tidy: sync go.mod/go.sum
tidy:
	$(GO) mod tidy

## cli: build the headless reconcli binary (no system deps)
cli:
	$(GO) build -o build/bin/reconcli ./cmd/reconcli

## gui: build the Wails desktop app (requires wails + webkit2gtk-4.1)
gui:
	wails build -tags $(TAGS)

## run: run the Wails app in dev mode
run:
	wails dev -tags $(TAGS)

## build: build everything buildable without a GUI toolchain
build: cli

clean:
	rm -rf build/bin
