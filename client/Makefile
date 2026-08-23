# skillctl — the SkillTrust client
#
# Everything here runs offline. `make check` is what CI runs.
.PHONY: build check fmt lint test snapshot install clean release notarize plugin

GOFLAGS ?=
VERSION ?= dev

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/skillctl ./cmd/skillctl

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
	goreleaser release --clean

notarize:
	./scripts/notarize-macos.sh dist

clean:
	rm -rf bin dist

# Assemble the Claude Code plugin: one binary per platform, chosen at run time by bin/skillctl.
#
# The binaries are build output and are not committed. A marketplace serves this plugin either
# from a repository that ran this target in CI, or from a release archive; committing ~40 MB of
# executables to keep `git clone` self-contained would make every unrelated change to this
# repository expensive forever.
PLUGIN_BIN := ../plugin/bin
PLUGIN_TARGETS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64

plugin:
	@for target in $(PLUGIN_TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; \
		out="$(PLUGIN_BIN)/skillctl-$${os}-$${arch}"; \
		if [ "$${os}" = "windows" ]; then out="$${out}.exe"; fi; \
		echo "  $${os}/$${arch}"; \
		GOOS=$${os} GOARCH=$${arch} CGO_ENABLED=0 go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" -o "$${out}" ./cmd/skillctl || exit 1; \
	done
	@echo "plugin assembled in $(PLUGIN_BIN)"
