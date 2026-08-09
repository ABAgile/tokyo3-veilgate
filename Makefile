GO ?= go
BIN_DIR ?= bin
VEILGATED_BIN := $(BIN_DIR)/veilgated
IMAGE_NAME ?= tokyo3-veilgate
IMAGE_TAG ?= dev
IMAGE := $(IMAGE_NAME):$(IMAGE_TAG)
TARGETARCH ?= $(shell $(GO) env GOARCH)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VEILGATED_CONSOLE_PORT ?= 8081
VEILGATED_PROXY_PORT ?= 8080
INTERCEPT_CA_CERT ?= config/intercept-ca.crt
INTERCEPT_CA_KEY ?= config/intercept-ca.key
PROXY_CERT ?= config/proxy.crt
PROXY_KEY ?= config/proxy.key
CONSOLE_CERT ?= config/console.crt
CONSOLE_KEY ?= config/console.key
MKCERT ?= mkcert
PROXY_CERT_SAN ?= DNS:veilgated-proxy,DNS:veilgated,DNS:localhost,IP:127.0.0.1,IP:::1
CONSOLE_CERT_HOSTS ?= localhost 127.0.0.1 ::1 veilgated.localhost veilgated
VEILGATED_INTERCEPT_CA_CERT ?= /etc/veilgate/$(notdir $(INTERCEPT_CA_CERT))
VEILGATED_INTERCEPT_CA_KEY ?= /etc/veilgate/$(notdir $(INTERCEPT_CA_KEY))
VEILGATED_PROXY_CERT ?= /etc/veilgate/$(notdir $(PROXY_CERT))
VEILGATED_PROXY_KEY ?= /etc/veilgate/$(notdir $(PROXY_KEY))
VEILGATED_CONSOLE_CERT ?= /etc/veilgate/$(notdir $(CONSOLE_CERT))
VEILGATED_CONSOLE_KEY ?= /etc/veilgate/$(notdir $(CONSOLE_KEY))
export VEILGATED_CONSOLE_PORT VEILGATED_PROXY_PORT
export VEILGATED_INTERCEPT_CA_CERT VEILGATED_INTERCEPT_CA_KEY
export VEILGATED_PROXY_CERT VEILGATED_PROXY_KEY
export VEILGATED_CONSOLE_CERT VEILGATED_CONSOLE_KEY

.PHONY: build gen-ca gen-console-cert gen-cert check docker-build docker-up docker-down clean

## build: Compile the static Linux veilgated binary into ./bin/.
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(TARGETARCH) $(GO) build \
	  -trimpath -ldflags="-s -w -X main.Version=$(VERSION)" \
	  -o $(VEILGATED_BIN) ./cmd/veilgated

## gen-ca: Generate the local development TLS interception CA once.
gen-ca: build
	@mkdir -p config
	@if [ -f $(INTERCEPT_CA_CERT) ] && [ -f $(INTERCEPT_CA_KEY) ]; then \
	  echo "  using existing $(INTERCEPT_CA_CERT)"; \
	elif [ -e $(INTERCEPT_CA_CERT) ] || [ -e $(INTERCEPT_CA_KEY) ]; then \
	  echo "  interception CA is incomplete; remove the remaining file and retry" >&2; exit 1; \
	else \
	  $(VEILGATED_BIN) ca init --cert $(INTERCEPT_CA_CERT) --key $(INTERCEPT_CA_KEY); \
	fi

## gen-console-cert: Generate an HTTPS console certificate signed by the local mkcert root CA.
gen-console-cert:
	@set -eu; \
	command -v "$(MKCERT)" >/dev/null || { echo "$(MKCERT) is required; install mkcert first" >&2; exit 1; }; \
	root_dir="$$($(MKCERT) -CAROOT)"; \
	root_ca="$$root_dir/rootCA.pem"; \
	root_key="$$root_dir/rootCA-key.pem"; \
	test -r "$$root_ca" && test -r "$$root_key" || { echo "mkcert root CA and key not found under $$root_dir; run '$(MKCERT) -install' first" >&2; exit 1; }; \
	umask 077; \
	mkdir -p "$(dir $(CONSOLE_CERT))" "$(dir $(CONSOLE_KEY))"; \
	if [ -f "$(CONSOLE_CERT)" ] && [ -f "$(CONSOLE_KEY)" ]; then \
		echo "  using existing $(CONSOLE_CERT) and $(CONSOLE_KEY) signed by $$root_ca"; \
	elif [ -e "$(CONSOLE_CERT)" ] || [ -e "$(CONSOLE_KEY)" ]; then \
		echo "  console certificate is incomplete; remove the remaining file and retry" >&2; exit 1; \
	else \
		"$(MKCERT)" -cert-file "$(CONSOLE_CERT)" -key-file "$(CONSOLE_KEY)" $(CONSOLE_CERT_HOSTS); \
		chmod 644 "$(CONSOLE_CERT)"; chmod 600 "$(CONSOLE_KEY)"; \
		echo "  wrote $(CONSOLE_CERT) and $(CONSOLE_KEY) signed by $$root_ca"; \
	fi

## gen-cert: Generate interception CA, proxy, and console certificates once.
gen-cert: gen-ca gen-console-cert
	@set -eu; \
	umask 077; \
	mkdir -p "$(dir $(PROXY_CERT))" "$(dir $(PROXY_KEY))"; \
	if [ -f "$(PROXY_CERT)" ] && [ -f "$(PROXY_KEY)" ]; then \
		echo "  using existing $(PROXY_CERT) and $(PROXY_KEY)"; \
	elif [ -e "$(PROXY_CERT)" ] || [ -e "$(PROXY_KEY)" ]; then \
		echo "  proxy certificate is incomplete; remove the remaining file and retry" >&2; exit 1; \
	else \
		$(VEILGATED_BIN) ca sign \
			--ca-cert "$(INTERCEPT_CA_CERT)" \
			--ca-key "$(INTERCEPT_CA_KEY)" \
			--cert "$(PROXY_CERT)" \
			--key "$(PROXY_KEY)" \
			--san "$(PROXY_CERT_SAN)"; \
		chmod 644 "$(PROXY_CERT)"; chmod 600 "$(PROXY_KEY)"; \
		echo "  wrote $(PROXY_CERT) and $(PROXY_KEY) signed by $(INTERCEPT_CA_CERT)"; \
	fi

# ── Quality ───────────────────────────────────────────────────────────────────

## check: Full pre-commit sequence (gofmt + tidy + test + vet + staticcheck + gopls + govulncheck + deadcode)
check:
	gofmt -s -w .
	$(GO) mod tidy
	$(GO) test ./... -count=1
	$(GO) vet ./...
	staticcheck ./...
	find . -type f -name "*.go" -print0 | xargs -0 -n 100 gopls check -severity=hint
	govulncheck ./...
	@out=$$(deadcode -test ./...); if [ -n "$$out" ]; then echo "$$out"; echo "deadcode: unreachable functions found (above)"; exit 1; fi


# ── Docker ────────────────────────────────────────────────────────────────────

## docker-build: Build the binary, then package it as the local Docker image.
docker-build: build
	docker build \
	  --platform linux/$(TARGETARCH) \
	  --build-arg VERSION=$(VERSION) \
	  -t $(IMAGE) .

## docker-up: Build, package, and start Veilgate on tokyo3_hq_sandbox.
docker-up: gen-cert docker-build
	@docker network inspect tokyo3_hq_sandbox >/dev/null 2>&1 || \
	  docker network create tokyo3_hq_sandbox >/dev/null
	@docker network inspect tokyo3_hq_default >/dev/null 2>&1 || \
	  { echo "tokyo3_hq_default management network is required" >&2; exit 1; }
	VEILGATE_IMAGE=$(IMAGE) docker compose -f compose.yml up -d --no-build --wait --remove-orphans
	@echo "  proxy:   https://veilgated-proxy:$(VEILGATED_PROXY_PORT) on tokyo3_hq_sandbox"
	@echo "  console: https://127.0.0.1:$(VEILGATED_CONSOLE_PORT)"
	@echo "  proxy trust:   $(INTERCEPT_CA_CERT)"
	@echo "  console trust: $$(mkcert -CAROOT)/rootCA.pem"

## docker-down: Stop the Compose test deployment.
docker-down:
	VEILGATE_IMAGE=$(IMAGE) docker compose -f compose.yml down --remove-orphans

## clean: Remove locally built binaries.
clean:
	rm -rf $(BIN_DIR)

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help
help:
	@awk '/^##/ { \
	  line=$$0; sub(/^## ?/, "", line); \
	  if (line ~ /^[a-z0-9_.-]+:/) { \
	    target=line; sub(/:.*/, "", target); \
	    desc=line; sub(/^[^:]+:[[:space:]]*/, "", desc); \
	    names[++n]=target; docs[target]=desc; \
	  } else header[++h]=line; \
	} END { \
	  for (i=1; i<=h; i++) print header[i]; \
	  for (i=1; i<=n; i++) for (j=i+1; j<=n; j++) if (names[j] < names[i]) { tmp=names[i]; names[i]=names[j]; names[j]=tmp } \
	  for (i=1; i<=n; i++) printf "  %-22s %s\n", names[i], docs[names[i]]; \
	}' $(MAKEFILE_LIST)
