BINARY := bin/nvme-guard

.PHONY: build test bpf integration clean

build:
	@mkdir -p bin
	go build -o $(BINARY) ./cmd/nvme-guard

test:
	go test ./...

bpf:
	@echo "bpf build not wired yet"

integration:
	@echo "integration harness not wired yet"

clean:
	@rm -f $(BINARY)
