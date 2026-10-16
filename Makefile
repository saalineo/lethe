.PHONY: all transport client check clean run-server run-client

TRANSPORT_DIR := libtransport
CLIENT_DIR := cli
LIB := target/release/liblethe.so
BIN := target/release/lethe
DEST := target/release

all: transport client
	@echo ""
	@echo "LETHE build complete."
	@echo "  Transport:  $(LIB)"
	@echo "  Client: $(BIN)"
	@echo ""
	@echo "Run:"
	@echo "  Server: cd $(DEST) && ./lethe --server --addr 0.0.0.0:9000 --lib ./liblethe.so"
	@echo "  Client: cd $(DEST) && ./lethe --addr 127.0.0.1:9000 --lib ./liblethe.so"
	@echo "  Tor:    ./lethe --server --onion --lib ./liblethe.so   (peer: ./lethe --onion --lib ./liblethe.so)"

transport:
	cargo build --release --locked -p lethe-transport

client:
	cargo build --release --locked -p lethe

# Lints (warnings are errors) and unit tests for both crates.
check:
	cargo clippy --workspace --all-targets --locked -- -D warnings
	cargo test --workspace --locked

run-server: all
	cd $(DEST) && ./lethe --server --addr 0.0.0.0:9000 --lib ./liblethe.so

run-client: all
	cd $(DEST) && ./lethe --addr 127.0.0.1:9000 --lib ./liblethe.so

clean:
	cargo clean
