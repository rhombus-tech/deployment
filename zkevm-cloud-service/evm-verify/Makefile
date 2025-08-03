.PHONY: all build test examples clean

all: build test examples

build:
	cargo build

test:
	cargo test

examples: build
	@echo "Running unified API example..."
	cargo run --example unified_api_example
	@echo "\nRunning proof verification example..."
	cargo run --example proof_verification_example

clean:
	cargo clean

# Individual examples
unified-example:
	cargo run --example unified_api_example

proof-example:
	cargo run --example proof_verification_example
