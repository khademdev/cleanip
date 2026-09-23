BINARY  := cleanip
LDFLAGS := -s -w

.PHONY: build build-windows build-linux build-macos build-all run fmt vet test tidy clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath \
		-ldflags="$(LDFLAGS) -H windowsgui" -o $(BINARY).exe .

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
		-ldflags="$(LDFLAGS)" -o $(BINARY)-linux .

build-macos:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath \
		-ldflags="$(LDFLAGS)" -o $(BINARY)-macos .

build-all: build-windows build-linux build-macos

run: build
	./$(BINARY)

fmt:  ; gofmt -w .
vet:  ; go vet ./...
test: ; go test -v ./...
tidy: ; go mod tidy

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-linux $(BINARY)-macos
