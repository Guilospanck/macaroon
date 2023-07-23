run-all-check:
	cargo check --all-targets

run-all-tests:
	cargo test --tests

run-all-clippy:
	cargo clippy --all-targets -- -D warnings

all: run-all-check run-all-tests run-all-clippy
	