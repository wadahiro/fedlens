.PHONY: build dev test e2e e2e-capture screenshots generate clean

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

# Run E2E tests (Playwright, retain artifacts on failure only)
e2e:
	docker compose up -d --build --wait
	cd e2e && npx playwright test
	docker compose down

# Run E2E tests in capture mode (always save video/trace/screenshot)
e2e-capture:
	docker compose up -d --build --wait
	cd e2e && CAPTURE=1 npx playwright test
	docker compose down

# Take screenshots for README (Chromium only, then optimize to JPEG)
screenshots:
	mkdir -p docs/screenshots
	docker compose up -d --build --wait
	cd e2e && npx playwright test tests/screenshots.spec.ts --project=chromium
	docker compose down
	sips -s format jpeg -s formatOptions 85 docs/screenshots/oidc-post-login.png --out docs/screenshots/oidc-post-login.jpg
	sips -s format jpeg -s formatOptions 85 docs/screenshots/saml-post-login.png --out docs/screenshots/saml-post-login.jpg
	rm -f docs/screenshots/*.png

# Clean build artifacts
clean:
	rm -f $(BINARY)
	find . -name '*_templ.go' -delete
