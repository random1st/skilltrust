# skillctl — the SkillTrust client
#
# Everything here runs offline. `make check` is what CI runs.
.PHONY: build check fmt lint test snapshot install clean release notarize

GOFLAGS ?=
VERSION ?= dev

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/skillctl ./cmd/skillctl

check: fmt lint test

fmt:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

lint:
	go vet ./...

test:
	go test -race -cover ./...

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
