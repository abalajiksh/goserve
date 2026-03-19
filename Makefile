VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS  = -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build clean

build:
	go build -ldflags '$(LDFLAGS)' -o goserve .

clean:
	rm -f goserve goserve-*

# Cross-compilation targets
linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o goserve-linux-arm64 .

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o goserve-linux-amd64 .

darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o goserve-darwin-arm64 .

windows:
	GOOS=windows GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o goserve.exe .

all: linux-arm64 linux-amd64 darwin-arm64 windows
