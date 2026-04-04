APP := mythnet
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build clean all frontend install uninstall

frontend:
	cd web && npm install --silent && npm run build

build: frontend
	go build $(LDFLAGS) -o $(APP) ./cmd/mythnet

all: frontend linux-amd64 linux-arm64 linux-arm darwin-amd64 darwin-arm64 windows-amd64

linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(APP)-linux-amd64 ./cmd/mythnet

linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(APP)-linux-arm64 ./cmd/mythnet

linux-arm:
	GOOS=linux GOARCH=arm GOARM=7 go build $(LDFLAGS) -o dist/$(APP)-linux-armv7 ./cmd/mythnet

darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(APP)-darwin-amd64 ./cmd/mythnet

darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(APP)-darwin-arm64 ./cmd/mythnet

windows-amd64:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(APP)-windows-amd64.exe ./cmd/mythnet

install: build
	install -d /usr/local/bin
	install -m 755 $(APP) /usr/local/bin/$(APP)
	install -d /etc/mythnet
	test -f /etc/mythnet/config.yaml || install -m 644 config.example.yaml /etc/mythnet/config.yaml
	install -d /var/lib/mythnet
	install -m 644 mythnet.service /etc/systemd/system/mythnet.service
	@echo ""
	@echo "Installed. To start:"
	@echo "  sudo useradd -r -s /bin/false mythnet"
	@echo "  sudo chown -R mythnet:mythnet /var/lib/mythnet"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now mythnet"

uninstall:
	systemctl stop mythnet 2>/dev/null || true
	systemctl disable mythnet 2>/dev/null || true
	rm -f /etc/systemd/system/mythnet.service
	rm -f /usr/local/bin/$(APP)
	@echo "Removed binary and service. Config and data left in /etc/mythnet and /var/lib/mythnet."

clean:
	rm -rf $(APP) dist/ web/build web/node_modules
