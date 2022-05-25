all: build

.PHONY: all doc

SHELL := /bin/bash

# 'test' or 'ci'
TARGET ?= test
ci:
	TARGET=ci make test

init-rust-i686-nightly:
	rustup toolchain install nightly-i686-unknown-linux-gnu
	rustup target add i686-unknown-linux-gnu
init-rust-x86_64-nightly:
	rustup toolchain install nightly-x86_64-unknown-linux-gnu
	rustup target add x86_64-unknown-linux-gnu

doc:
	cargo doc --no-deps
doc-sync: doc
	rm -rf doc
	rsync -az target/doc/ doc/
	rm doc/.lock
build:
	cargo build --lib --release
#build-i686:
#	cargo +nightly-i686-unknown-linux-gnu build --lib --release --target i686-unknown-linux-gnu --no-default-features

test-nostd:
	cargo test --no-default-features --features "sign validate"
test-std:
	cargo test --no-default-features --features "std sign validate"
#test-i686:
#	cargo +nightly-i686-unknown-linux-gnu test --target i686-unknown-linux-gnu \
#		--no-default-features --features "sign-lts validate-lts"
test-example-rust-mbedtls:
	make -C examples/rust-mbedtls test

test:
	make test-nostd
	make test-std
	#if [ "$$TARGET" = "ci" ]; then make test-i686; fi
	make test-example-rust-mbedtls
