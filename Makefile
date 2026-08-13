## veilgate — build targets
##
## Usage: make <target>
##

# ── Variables ─────────────────────────────────────────────────────────────────

MODULE          := github.com/abagile/veilgate
CMD_VEILGATED   := ./cmd/veilgated

BIN_DIR         := bin
VEILGATED_BIN   := $(BIN_DIR)/veilgated

GIT_TAG    := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION    := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

LDFLAGS := -s -w -X main.Version=$(VERSION)

GO      := go
GOFLAGS :=

TARGETARCH ?= arm64

IMAGE_NAME     ?= abagile/tokyo3-veilgate
IMAGE_TAG      ?= $(VERSION)
IMAGE          := $(IMAGE_NAME):$(IMAGE_TAG)

COMPOSE_PROJECT_NAME        ?= tokyo3_veilgate
VEILGATE_CONFIG_VOLUME      ?= tokyo3_hq_proj
VEILGATE_CONFIG_SUBPATH     ?= abagile/veilgate/config
VEILGATE_SANDBOX_NETWORK    ?= tokyo3_hq_sandbox
VEILGATE_MANAGEMENT_NETWORK ?= tokyo3_hq_default
DATA_VOLUME                 := $(COMPOSE_PROJECT_NAME)_data
# The development rig uses project files owned by the local development user.
# Registry installations should override these to match the prepared volume.
VEILGATE_UID               ?= 1000
VEILGATE_GID               ?= 1000

VEILGATED_CONSOLE_PORT     ?= 8081
VEILGATED_PROXY_PORT       ?= 8080
VEILGATED_CONSOLE_USERNAME ?= admin
VEILGATED_CONSOLE_PASSWORD ?= admin

INTERCEPT_CA_CERT ?= config/intercept-ca.crt
INTERCEPT_CA_KEY  ?= config/intercept-ca.key
PROXY_CERT        ?= config/proxy.crt
PROXY_KEY         ?= config/proxy.key
CONSOLE_CERT      ?= config/console.crt
CONSOLE_KEY       ?= config/console.key
MKCERT            ?= mkcert
PROXY_CERT_SAN    ?= DNS:veilgated-proxy,DNS:veilgated,DNS:localhost,IP:127.0.0.1,IP:::1
CONSOLE_CERT_HOSTS ?= localhost 127.0.0.1 ::1 veilgated.localhost veilgated

export COMPOSE_PROJECT_NAME
export VEILGATE_CONFIG_VOLUME VEILGATE_CONFIG_SUBPATH
export VEILGATE_SANDBOX_NETWORK VEILGATE_MANAGEMENT_NETWORK
export VEILGATE_UID VEILGATE_GID
export VEILGATED_CONSOLE_PORT VEILGATED_PROXY_PORT
export VEILGATED_CONSOLE_USERNAME VEILGATED_CONSOLE_PASSWORD

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-linux build-linux-amd64 build-darwin \
        test test-verbose tidy vet lint check \
        gen-ca gen-console-cert gen-certs \
        docker-build docker-build-amd64 docker-push \
        docker-up docker-down \
        install clean clean-all help

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

## build: Compile veilgated into ./bin/.
build: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(VEILGATED_BIN) $(CMD_VEILGATED)
	@echo "  built $(VEILGATED_BIN) ($(VERSION))"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

## build-linux: Cross-compile veilgated for Linux arm64 (Graviton, default).
build-linux: $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/veilgated-linux-arm64 $(CMD_VEILGATED)
	@echo "  built veilgated-linux-arm64"

## build-linux-amd64: Cross-compile veilgated for Linux amd64.
build-linux-amd64: $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/veilgated-linux-amd64 $(CMD_VEILGATED)
	@echo "  built veilgated-linux-amd64"

## build-darwin: Cross-compile veilgated for macOS arm64.
build-darwin: $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/veilgated-darwin-arm64 $(CMD_VEILGATED)
	@echo "  built veilgated-darwin-arm64"

# ── Quality ───────────────────────────────────────────────────────────────────

## test: Run all tests.
test:
	$(GO) test ./... -count=1

## test-verbose: Run all tests with verbose output.
test-verbose:
	$(GO) test ./... -count=1 -v

## tidy: Run go mod tidy.
tidy:
	$(GO) mod tidy

## vet: Run go vet.
vet:
	$(GO) vet ./...

## lint: Run staticcheck.
lint:
	staticcheck ./...

## check: Full pre-commit sequence (gofmt + tidy + frontend tests + Go quality checks).
check:
	gofmt -s -w .
	$(GO) mod tidy
	node --check internal/console/static/app.js
	node --check internal/console/static/formatters.js
	node --test internal/console/formatters_test.mjs
	$(GO) test ./... -count=1
	$(GO) vet ./...
	staticcheck ./...
	find . -type f -name "*.go" -print0 | xargs -0 -n 100 gopls check -severity=hint
	govulncheck ./...
	@out=$$(deadcode -test ./...); if [ -n "$$out" ]; then echo "$$out"; echo "deadcode: unreachable functions found (above)"; exit 1; fi

# ── Development certificates ─────────────────────────────────────────────────

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

## gen-certs: Generate interception CA, proxy, and console certificates once.
gen-certs: gen-ca gen-console-cert
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

# ── Docker ────────────────────────────────────────────────────────────────────

## docker-build: Build the Veilgate Docker image (linux/arm64, default).
docker-build:
	docker build \
	  --platform linux/$(TARGETARCH) \
	  --build-arg TARGETOS=linux \
	  --build-arg TARGETARCH=$(TARGETARCH) \
	  --build-arg VERSION=$(VERSION) \
	  --target server \
	  -t $(IMAGE_NAME):$(IMAGE_TAG) \
	  -t $(IMAGE_NAME):latest \
	  .
	@echo "  built $(IMAGE_NAME):$(IMAGE_TAG)"

## docker-build-amd64: Build the Veilgate Docker image for linux/amd64.
docker-build-amd64:
	docker build \
	  --platform linux/amd64 \
	  --build-arg TARGETOS=linux \
	  --build-arg TARGETARCH=amd64 \
	  --build-arg VERSION=$(VERSION) \
	  --target server \
	  -t $(IMAGE_NAME):$(IMAGE_TAG)-amd64 \
	  .

## docker-push: Push the image to the configured registry.
docker-push: docker-build
	docker push $(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(IMAGE_NAME):latest

# ── Dev rig (docker compose) ──────────────────────────────────────────────────

## docker-up: Generate dev certificates and bring up the Compose rig.
docker-up: gen-certs
	@docker network create $(VEILGATE_SANDBOX_NETWORK) >/dev/null 2>&1 || true
	@docker network inspect $(VEILGATE_MANAGEMENT_NETWORK) >/dev/null 2>&1 || \
	  { echo "$(VEILGATE_MANAGEMENT_NETWORK) management network is required" >&2; exit 1; }
	@docker volume inspect $(VEILGATE_CONFIG_VOLUME) >/dev/null 2>&1 || \
	  { echo "$(VEILGATE_CONFIG_VOLUME) config volume is required; provision it before docker-up" >&2; exit 1; }
	@docker volume inspect $(DATA_VOLUME) >/dev/null 2>&1 || \
	  { echo "$(DATA_VOLUME) data volume is required; create and chown it to $(VEILGATE_UID):$(VEILGATE_GID) before docker-up" >&2; exit 1; }
	docker compose -f compose.yml up -d --build --wait --remove-orphans
	@echo "  proxy:   https://veilgated-proxy:$(VEILGATED_PROXY_PORT) on $(VEILGATE_SANDBOX_NETWORK)"
	@echo "  console: https://127.0.0.1:$(VEILGATED_CONSOLE_PORT)"
	@echo "  proxy trust:   $(INTERCEPT_CA_CERT)"
	@echo "  console trust: $$(mkcert -CAROOT)/rootCA.pem"

## docker-down: Stop the Compose test deployment (preserves volumes).
docker-down:
	docker compose -f compose.yml down --remove-orphans

# ── Install / Clean ───────────────────────────────────────────────────────────

## install: Install veilgated to GOPATH/bin (or ~/go/bin).
install:
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_VEILGATED)
	@echo "  installed veilgated"

## clean: Remove ./bin/.
clean:
	rm -rf $(BIN_DIR)

## clean-all: Stop Compose and remove local data volumes and build artifacts.
clean-all: clean
	docker compose -f compose.yml down --remove-orphans -v 2>/dev/null || true
	@echo "  removed local Compose data volume and build artifacts"

# ── Help ─────────────────────────────────────────────────────────────────────

## help: Show this help.
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
