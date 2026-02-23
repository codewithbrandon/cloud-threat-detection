# =============================================================================
# Makefile — Cloud-Native Threat Detection Platform
# =============================================================================
# Usage: make <target>
# Run `make help` to see all available targets

NAMESPACE       := threat-detection
APP_NAME        := threat-detection-app
IMAGE_NAME      := threat-detection-app
IMAGE_TAG       := 1.0.0
TARGET_URL      := http://localhost:8080
PROMETHEUS_URL  := http://localhost:9090
KUBECTL         := kubectl
DOCKER          := docker

.DEFAULT_GOAL := help

.PHONY: help build push deploy deploy-monitoring deploy-falco \
        attack-brute attack-cpu attack-memory attack-exec attack-all \
        port-forward logs status clean verify

help: ## Show this help message
	@echo "Cloud-Native Threat Detection Platform"
	@echo "======================================="
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# =============================================================================
# BUILD
# =============================================================================

build: ## Build the Docker image
	@echo "Building $(IMAGE_NAME):$(IMAGE_TAG)..."
	$(DOCKER) build -f docker/Dockerfile -t $(IMAGE_NAME):$(IMAGE_TAG) app/
	@echo "Build complete."

push: build ## Build and push image to registry
	$(DOCKER) push $(IMAGE_NAME):$(IMAGE_TAG)

# =============================================================================
# DEPLOY
# =============================================================================

deploy-namespace: ## Create namespace and security baseline
	$(KUBECTL) apply -f k8s/namespace.yaml
	$(KUBECTL) apply -f k8s/serviceaccount.yaml
	$(KUBECTL) apply -f k8s/resource-quota.yaml

deploy-monitoring: deploy-namespace ## Deploy Prometheus + Alertmanager + Loki + Grafana
	$(KUBECTL) apply -f monitoring/prometheus/prometheus-deployment.yaml
	$(KUBECTL) apply -f monitoring/prometheus/prometheus-config.yaml
	$(KUBECTL) apply -f monitoring/prometheus/alert-rules.yaml
	$(KUBECTL) apply -f monitoring/alertmanager/alertmanager-deployment.yaml
	$(KUBECTL) apply -f monitoring/alertmanager/alertmanager-config.yaml
	$(KUBECTL) apply -f monitoring/loki/loki-deployment.yaml
	$(KUBECTL) apply -f monitoring/grafana/grafana-deployment.yaml
	@echo "Monitoring stack deployed. Waiting for pods..."
	$(KUBECTL) wait --for=condition=Ready pods -l component=monitoring -n $(NAMESPACE) --timeout=120s || true
	$(KUBECTL) wait --for=condition=Ready pods -l component=logging -n $(NAMESPACE) --timeout=120s || true

deploy-app: deploy-namespace ## Deploy the Flask application
	$(KUBECTL) apply -f k8s/configmap.yaml
	$(KUBECTL) apply -f k8s/deployment.yaml
	$(KUBECTL) apply -f k8s/service.yaml
	$(KUBECTL) wait --for=condition=Ready pods -l app=$(APP_NAME) -n $(NAMESPACE) --timeout=120s

deploy-network: ## Apply NetworkPolicies (do this last)
	$(KUBECTL) apply -f k8s/network-policy.yaml
	@echo "NetworkPolicy applied. Verify with: make status"

deploy: deploy-monitoring deploy-app deploy-network ## Deploy complete platform
	@echo ""
	@echo "Platform deployed! Run 'make port-forward' to access dashboards."

deploy-falco: ## Deploy Falco via Helm (requires Helm 3.x)
	helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
	helm repo update
	helm upgrade --install falco falcosecurity/falco \
		--namespace $(NAMESPACE) \
		--set driver.kind=modern_ebpf \
		--set falcosidekick.enabled=true \
		--set falcosidekick.config.alertmanager.hostport="http://alertmanager:9093" \
		--set falcosidekick.config.loki.hostport="http://loki:3100" \
		--set customRules."custom-rules\.yaml"="$$(cat monitoring/falco/falco-rules.yaml)"
	@echo "Falco deployed."

# =============================================================================
# ATTACK SIMULATION
# =============================================================================

attack-brute: ## Run brute force login simulation
	@echo "Running brute force attack simulation..."
	python3 attacks/brute_force.py --target $(TARGET_URL) --mode sequential --count 25 --rate 5

attack-brute-distributed: ## Run distributed credential stuffing
	python3 attacks/brute_force.py --target $(TARGET_URL) --mode distributed --count 60 --concurrency 4

attack-cpu: ## Run CPU spike simulation (90% intensity, 120s)
	@echo "Running CPU spike simulation..."
	python3 attacks/cpu_spike.py --target $(TARGET_URL) --intensity 0.9 --duration 120

attack-memory: ## Run memory exhaustion simulation
	@echo "Running memory exhaustion simulation..."
	python3 attacks/memory_exhaustion.py --target $(TARGET_URL) --mode escalating --size 450 --steps 4

attack-exec: ## Run suspicious command / kill chain simulation
	@echo "Running full kill chain simulation..."
	python3 attacks/suspicious_commands.py --target $(TARGET_URL) --scenario kill-chain

attack-all: ## Run all attack simulations sequentially
	@echo "Running full attack suite..."
	make attack-brute
	@sleep 30
	make attack-cpu
	@sleep 60
	make attack-memory
	@sleep 60
	make attack-exec
	@echo "All attacks complete. Check alerts at $(PROMETHEUS_URL)/alerts"

# =============================================================================
# OPERATIONS
# =============================================================================

port-forward: ## Port-forward all dashboards (background processes)
	$(KUBECTL) port-forward svc/grafana 3000:3000 -n $(NAMESPACE) &
	$(KUBECTL) port-forward svc/prometheus 9090:9090 -n $(NAMESPACE) &
	$(KUBECTL) port-forward svc/alertmanager 9093:9093 -n $(NAMESPACE) &
	$(KUBECTL) port-forward svc/$(APP_NAME) 8080:80 -n $(NAMESPACE) &
	@echo ""
	@echo "Dashboards available at:"
	@echo "  Grafana:      http://localhost:3000"
	@echo "  Prometheus:   http://localhost:9090"
	@echo "  Alertmanager: http://localhost:9093"
	@echo "  Application:  http://localhost:8080"

logs: ## Stream application logs
	$(KUBECTL) logs -f -l app=$(APP_NAME) -n $(NAMESPACE) --all-containers

logs-falco: ## Stream Falco runtime security alerts
	$(KUBECTL) logs -f -l app=falco -n $(NAMESPACE) | jq 'select(.rule != null)'

status: ## Show pod and alert status
	@echo "=== Pods ==="
	$(KUBECTL) get pods -n $(NAMESPACE) -o wide
	@echo ""
	@echo "=== Services ==="
	$(KUBECTL) get svc -n $(NAMESPACE)
	@echo ""
	@echo "=== NetworkPolicies ==="
	$(KUBECTL) get networkpolicies -n $(NAMESPACE)
	@echo ""
	@echo "=== Resource Usage ==="
	$(KUBECTL) top pods -n $(NAMESPACE) 2>/dev/null || echo "(metrics-server not available)"

verify: ## Verify Prometheus alerts are configured
	@echo "=== Checking Prometheus targets ==="
	curl -s $(PROMETHEUS_URL)/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health, lastScrape: .lastScrape}'
	@echo ""
	@echo "=== Checking alert rules ==="
	curl -s $(PROMETHEUS_URL)/api/v1/rules | jq '.data.groups[].rules[] | {name: .name, state: .state}'

# =============================================================================
# CLEANUP
# =============================================================================

clean: ## Delete all platform resources
	@echo "Deleting all resources in namespace $(NAMESPACE)..."
	$(KUBECTL) delete namespace $(NAMESPACE) --ignore-not-found
	@echo "Cleanup complete."

clean-attacks: ## Remove attack simulation result files
	rm -f attack-results-*.json forensics-*.txt forensics-*.yaml
