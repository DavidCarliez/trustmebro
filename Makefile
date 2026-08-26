BINARY := trustmebro

.PHONY: build test install release clean

build:
	go build -ldflags "-s -w" -o $(BINARY) .

test:
	go test ./...

install: build
	./$(BINARY) install

# Cross-compile release tarballs into dist/. Asset names are version-less so
# the "latest" download URL stays stable across releases.
release:
	mkdir -p dist
	for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${t%/*}; arch=$${t#*/}; ext=""; \
		[ "$$os" = windows ] && ext=.exe; \
		d=dist/build/$$os-$$arch; mkdir -p $$d; \
		GOOS=$$os GOARCH=$$arch go build -ldflags "-s -w" -o $$d/$(BINARY)$$ext .; \
		tar -C $$d -czf dist/$(BINARY)_$${os}_$${arch}.tar.gz $(BINARY)$$ext; \
	done
	rm -rf dist/build
	cd dist && sha256sum *.tar.gz > SHA256SUMS

clean:
	rm -rf dist $(BINARY)
