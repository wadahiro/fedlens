.PHONY: build dev test e2e generate clean

BINARY := fedlens

# Generate templ files and build binary
build: generate
	CGO_ENABLED=0 go build -o $(BINARY) .

# Generate templ templates
generate:
	go run github.com/a-h/templ/cmd/templ@v0.3.977 generate

# Development mode: generate and run
dev: generate
	go run .

# Run unit tests
test:
	go test ./...

# Run E2E tests (Playwright)
e2e:
	docker compose up -d --build --wait
	cd e2e && npx playwright test
	docker compose down

# Clean build artifacts
clean:
	rm -f $(BINARY)
	find . -name '*_templ.go' -delete
