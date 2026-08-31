# skillctl — the SkillTrust client
#
# Everything here runs offline. `make check` is what CI runs.
.PHONY: build check fmt lint test snapshot install clean release notarize plugin mcp

GOFLAGS ?=
VERSION ?= dev

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/skillctl ./cmd/skillctl

# The MCP server is a second binary, not a skillctl subcommand: the SDK brings nine
# dependencies, and skillctl decides whether a skill is trusted. `go version -m bin/skillctl`
# still lists two.
mcp:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/skilltrust-mcp ./cmd/skilltrust-mcp

check: fmt lint test

# The module lives at the repository root and internal/ is shared with the server, so
# ./... from this directory would quietly test the commands and skip every package they
# are built from. The module path pattern covers the whole module from anywhere.
MODULE := github.com/random1st/skilltrust/...

fmt:
	@test -z "$$(gofmt -l . ../internal ../server)" || (echo "gofmt needed:"; gofmt -l . ../internal ../server; exit 1)

lint:
	go vet $(MODULE)

test:
	go test -race -cover $(MODULE)

# Cross-compile every release target without publishing anything.
snapshot:
	goreleaser build --snapshot --clean

install:
	go install -trimpath ./cmd/skillctl

# Prove the reproducibility claim rather than asserting it: two independent builds of the
# same source must produce identical bytes.
reproducible:
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.version=$(VERSION)" -o /tmp/skillctl-repro-a ./cmd/skillctl
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.version=$(VERSION)" -o /tmp/skillctl-repro-b ./cmd/skillctl
	@a=$$(shasum -a 256 /tmp/skillctl-repro-a | cut -d' ' -f1); \
	 b=$$(shasum -a 256 /tmp/skillctl-repro-b | cut -d' ' -f1); \
	 rm -f /tmp/skillctl-repro-a /tmp/skillctl-repro-b; \
	 if [ "$$a" = "$$b" ]; then echo "reproducible: $$a"; else echo "DIVERGED: $$a != $$b"; exit 1; fi

# Cut a release from this machine. The Developer ID key stays in the local keychain
# rather than being exported into CI secrets — see scripts/sign-macos.sh for why.
release:
	@test -n "$$APPLE_SIGNING_IDENTITY" || \
		{ echo "set APPLE_SIGNING_IDENTITY, e.g. \"Developer ID Application: Name (TEAMID)\""; exit 1; }
	@test -n "$$GITHUB_TOKEN" || \
		{ echo "set GITHUB_TOKEN (e.g. GITHUB_TOKEN=\$$(gh auth token)) — it creates the release and pushes the cask to random1st/homebrew-tap, so it needs repo scope on both"; exit 1; }
	goreleaser release --clean

notarize:
	./scripts/notarize-macos.sh dist

clean:
	rm -rf bin dist

# The plugin is hooks only. A file named skillctl in plugin/bin would go on PATH inside a
# Claude Code session and intercept the release binary — including a wrapper that exits 0
# and leaves the session unverified. Cross-compilation of the real binary is the
# cross-compile CI job, not this target.
plugin:
	@if [ -e ../plugin/bin/skillctl ] || [ -e ../plugin/bin/skillctl.cmd ]; then \
		echo "plugin/bin must not contain a skillctl shim: it shadows the release binary on PATH"; \
		ls -la ../plugin/bin; \
		exit 1; \
	fi
	@test -f ../plugin/hooks/hooks.json
	@echo "plugin is hooks only; skillctl comes from a release"
