all: build

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

build:
	cargo build --lib --release
build-i686:
	cargo +nightly-i686-unknown-linux-gnu build --lib --release --target i686-unknown-linux-gnu --no-default-features

test-nostd:
	cargo test --no-default-features --features "sign validate"
test-nostd-lts:
	cargo test --no-default-features --features "sign-lts validate-lts"
test-std:
	cargo test --no-default-features --features "std sign validate"
test-std-lts:
	cargo test --no-default-features --features "std sign-lts validate-lts"
test-i686:
	cargo +nightly-i686-unknown-linux-gnu test --target i686-unknown-linux-gnu \
		--no-default-features --features "sign-lts validate-lts"
test:
	make test-nostd
	make test-nostd-lts
	make test-std
	make test-std-lts
