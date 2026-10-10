BIN := $(CURDIR)/core/target/release/proofgate

.PHONY: build test examples site demo clean

build:
	cd core && cargo build --release
	cd gateway && go build -o ../bin/proofgate-gateway ./cmd/proofgate-gateway

test: build
	cd core && cargo test
	cd gateway && PROOFGATE_BIN=$(BIN) go test -race -count=1 ./...
	cd dsl && PROOFGATE_BIN=$(BIN) ruby -Ilib -Itest test/builder_test.rb

# Recompile the example policies after editing a .rb file. CI fails if they are stale.
examples:
	for f in examples/deploys/*.rb; do ruby dsl/bin/proofgate-rb compile $$f -o $${f%.rb}.json; done

site:
	./scripts/build-site.sh

demo: build
	./scripts/demo.sh

clean:
	rm -rf bin _site core/target
