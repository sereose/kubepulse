VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X main.version=$(VERSION)

.PHONY: build test lint run release clean

build:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o bin/kubepulse ./cmd/kubepulse

test:
	go test ./... -race -count=1

lint:
	go vet ./...

run: build
	./bin/kubepulse

# Cross-compile the binaries people actually download.
release:
	@mkdir -p dist
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/kubepulse-linux-amd64  ./cmd/kubepulse
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/kubepulse-linux-arm64  ./cmd/kubepulse
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/kubepulse-darwin-amd64 ./cmd/kubepulse
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/kubepulse-darwin-arm64 ./cmd/kubepulse

clean:
	rm -rf bin dist
