all: test

test-nostd:
	cargo test --no-default-features --features "sign validate"
test-nostd-lts:
	cargo test --no-default-features --features "sign-lts validate-lts"
test-std:
	cargo test --no-default-features --features "std sign validate"
test-std-lts:
	cargo test --no-default-features --features "std sign-lts validate-lts"

test:
	make test-nostd
	make test-nostd-lts
	make test-std
	make test-std-lts
