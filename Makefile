VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.3.0-dev)
LDFLAGS := -s -w -X github.com/ManintheiCloud/Hardex.Version=$(VERSION)
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0

.PHONY: build test check fmt vet vuln docs selfcheck fuzz clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/hardex ./cmd/hardex

test:
	go test -race -count=1 ./...

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

vuln:
	go run $(GOVULNCHECK) ./...

fuzz:
	go test -run='^$$' -fuzz=FuzzLoad -fuzztime=60s ./core/resource

docs:
	go run ./tools/gendocs

# Hardex must pass its own restricted profile on the hardened fixtures and
# must fail on the insecure ones.
selfcheck: build
	./bin/hardex scan --profile restricted tests/fixtures/hardened
	@./bin/hardex scan --fail-on critical tests/fixtures/insecure > /dev/null; test $$? -eq 1

check: fmt vet test selfcheck

clean:
	rm -rf bin
