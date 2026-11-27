# osint-forge — build & test
#
# The app is a Go web server (default http://127.0.0.1:8081) with the Svelte
# UI embedded. Needs Go + Node/npm to build; no GUI/system libraries.

GO ?= go

# The root package embeds frontend/dist (go:embed), so building, vetting or
# testing it needs the UI built at least once.
DIST := frontend/dist/index.html

.PHONY: all test race vet build cli web frontend run clean fmt tidy

all: test vet build

## test: run ALL unit tests (engine packages + the web server's own tests)
test: $(DIST)
	$(GO) test ./...

## race: the same tests with the race detector (needs cgo), as CI runs them
race: $(DIST)
	$(GO) test -race ./...

## vet: static analysis of every package
vet: $(DIST)
	$(GO) vet ./...

## fmt: format all Go sources
fmt:
	$(GO) fmt ./...

## tidy: sync go.mod/go.sum
tidy:
	$(GO) mod tidy

## cli: build the headless reconcli binary (no system deps, no UI needed)
cli:
	$(GO) build -o build/bin/reconcli ./cmd/reconcli

## frontend: build the Svelte UI into frontend/dist (embedded into the binary)
frontend:
	cd frontend && npm install --no-audit --no-fund && npm run build

# Build the UI only when it has never been built (used by test/vet).
$(DIST):
	$(MAKE) frontend

## web: build the web server binary (UI embedded)
web: frontend
	$(GO) build -o build/bin/osint-forge .

## run: build and start the web UI on :8081
run: web
	./build/bin/osint-forge

## build: build everything
build: cli web

clean:
	rm -rf build/bin
