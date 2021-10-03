all: test

test:
	cargo test
	cargo test --features "std" -- --nocapture
