.PHONY: all transport client clean run-server run-client

TRANSPORT_DIR := libtransport
CLIENT_DIR := client
LIB := target/release/libsirfz.so
BIN := target/release/sirfz
DEST := target/release

all: transport client
	@echo ""
	@echo "SIRFZ build complete."
	@echo "  Transport:  $(LIB)"
	@echo "  Client: $(BIN)"
	@echo ""
	@echo "Run:"
	@echo "  Server: cd $(DEST) && ./sirfz --server --addr 0.0.0.0:9000 --lib ./libsirfz.so"
	@echo "  Client: cd $(DEST) && ./sirfz --addr 127.0.0.1:9000 --lib ./libsirfz.so"

transport:
	cargo build --release -p sirfz-transport

client:
	cargo build --release -p sirfz

run-server: all
	cd $(DEST) && ./sirfz --server --addr 0.0.0.0:9000 --lib ./libsirfz.so

run-client: all
	cd $(DEST) && ./sirfz --addr 127.0.0.1:9000 --lib ./libsirfz.so

clean:
	cargo clean
