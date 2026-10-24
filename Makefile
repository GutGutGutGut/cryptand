.PHONY: check test release linux-x86_64 linux-aarch64 clean

check:
	cargo fmt --all -- --check
	cargo check --locked

test:
	cargo test --locked

release: check test
	cargo build --release --locked

linux-x86_64:
	cargo build --release --locked \
		--target x86_64-unknown-linux-gnu

linux-aarch64:
	CROSS_CONTAINER_ENGINE=podman cross build --release --locked \
		--target aarch64-unknown-linux-gnu

clean:
	cargo clean
