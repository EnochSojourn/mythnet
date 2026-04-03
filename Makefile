APP := mythnet
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build clean all frontend

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

clean:
	rm -rf $(APP) dist/ web/build web/node_modules
