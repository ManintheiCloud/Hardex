VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.12.1-dev)
LDFLAGS := -s -w -X github.com/ManintheiCloud/Hardex.Version=$(VERSION)
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0

.PHONY: build test check fmt vet vuln docs selfcheck fuzz bench kustomize-check e2e corpus clean

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

# End-to-end check of `hardex fix --kustomize` with real Kustomize (needs
# kubectl): overlay the generated patches on a base and confirm the result
# no longer has the fixed findings.
kustomize-check: build
	@set -e; d=$$(mktemp -d); mkdir -p $$d/base; \
	cp tests/fixtures/insecure/workloads.yaml $$d/base/; \
	printf 'resources: [workloads.yaml]\n' > $$d/base/kustomization.yaml; \
	./bin/hardex fix $$d/base/workloads.yaml --max-risk high --out $$d/overlay --kustomize > /dev/null; \
	sed -i 's|  # - ../base|  - ../base|' $$d/overlay/kustomization.yaml; \
	kubectl kustomize $$d/overlay > $$d/out.yaml; \
	./bin/hardex scan --profile minimal --fail-on none $$d/out.yaml > $$d/scan.txt; \
	if grep -q 'HX-WL-001' $$d/scan.txt; then echo "kustomize overlay did not fix HX-WL-001"; exit 1; fi; \
	grep -q 'kind: NetworkPolicy' $$d/out.yaml || { echo "overlay resources missing"; exit 1; }; \
	echo "kustomize overlay verified"

bench:
	go test -run '^$$' -bench . -benchmem ./tests

docs:
	go run ./tools/gendocs

# Hardex must pass its own restricted profile on the hardened fixtures and
# must fail on the insecure ones.
selfcheck: build
	./bin/hardex scan --profile restricted tests/fixtures/hardened
	@./bin/hardex scan --fail-on critical tests/fixtures/insecure > /dev/null; test $$? -eq 1

check: fmt vet test selfcheck

# End-to-end on a real cluster (kind, docker, kubectl, jq). See tests/e2e/kind.sh.
e2e:
	tests/e2e/kind.sh

# Findings on pinned real-world manifests vs. reviewed golden files.
corpus: build
	tests/corpus/run.sh

clean:
	rm -rf bin
