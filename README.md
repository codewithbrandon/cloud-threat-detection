<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f0c29,50:302b63,100:24243e&height=200&section=header&text=Cloud-Native%20Threat%20Detection&fontSize=36&fontColor=ffffff&fontAlignY=38&desc=Infrastructure%20Monitoring%20Platform&descAlignY=58&descColor=a78bfa" width="100%"/>

<br/>

[![CI](https://github.com/codewithbrandon/cloud-threat-detection/actions/workflows/ci.yml/badge.svg)](https://github.com/codewithbrandon/cloud-threat-detection/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.29+-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)](https://kubernetes.io)
[![Prometheus](https://img.shields.io/badge/Prometheus-2.51-E6522C?style=for-the-badge&logo=prometheus&logoColor=white)](https://prometheus.io)
[![Grafana](https://img.shields.io/badge/Grafana-10.4-F46800?style=for-the-badge&logo=grafana&logoColor=white)](https://grafana.com)
[![Falco](https://img.shields.io/badge/Falco-0.38-00AEC7?style=for-the-badge&logo=falco&logoColor=white)](https://falco.org)
[![Docker](https://img.shields.io/badge/Docker-Multi--stage-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)

<br/>

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-11%20Tactics%20Covered-ff4444?style=flat-square&logo=target&logoColor=white)](docs/threat-model.md)
[![Alert Rules](https://img.shields.io/badge/Alert%20Rules-12%20Prometheus%20%7C%204%20LogQL-orange?style=flat-square&logo=bell&logoColor=white)](monitoring/prometheus/alert-rules.yaml)
[![Falco Rules](https://img.shields.io/badge/Falco%20Rules-9%20Custom%20Runtime-blue?style=flat-square&logo=shield&logoColor=white)](monitoring/falco/falco-rules.yaml)
[![Security](https://img.shields.io/badge/Security-Non--root%20%7C%20ReadOnly%20FS%20%7C%20Zero--trust%20Network-brightgreen?style=flat-square&logo=lock&logoColor=white)](k8s/network-policy.yaml)

<br/>

> **Production-grade runtime security, anomaly detection, and incident response for Kubernetes.**
> Three independent detection layers — Prometheus metrics, Loki logs, Falco syscalls —
> connected by Alertmanager and documented with real incident playbooks.

<br/>

[**Quick Start**](#-quick-start) • [**Architecture**](#-architecture) • [**Attack Simulation**](#-simulating-attacks) • [**Alert Reference**](#-alert-reference) • [**Interview Talking Points**](#-interview-talking-points)

</div>

---

## The Problem This Solves

```
Most Kubernetes environments have zero runtime visibility.
A compromised container can exfiltrate data, pivot laterally,
and mine crypto for weeks before anyone notices.
```

| Before | After |
|--------|-------|
| Shell spawned in container → **silent** | Shell spawned → Falco fires in **< 1 second** |
| 500 failed logins → **nobody knows** | 10 failed logins/2min → Slack alert + playbook link |
| Memory exhaustion → **surprise outage** | 75% memory threshold → warning before OOM kill |
| Pod crash loop → **user reports it** | 3 restarts/15min → PagerDuty page fires |
| "What do we do?" → **improvised** | SEC-001, SEC-002 playbooks → 15-min containment SLA |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    CLOUD-NATIVE THREAT DETECTION PLATFORM                       │
│                         Kubernetes Namespace: threat-detection                  │
└─────────────────────────────────────────────────────────────────────────────────┘

  ╔═══════════════════════════════════════════════════════════════════════════════╗
  ║  ATTACK SIMULATION LAYER                                                     ║
  ║  ┌──────────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ ║
  ║  │  brute_force.py  │  │ cpu_spike.py │  │ memory_ex.py │  │ kill_chain  │ ║
  ║  │  T1110 BruteForce│  │ T1499 DoS    │  │ T1499.004    │  │ Full APT sim│ ║
  ║  └────────┬─────────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ ║
  ╚═══════════╪════════════════════╪═════════════════╪══════════════════╪════════╝
              │      HTTP Requests │                 │                  │
  ╔═══════════▼════════════════════▼═════════════════▼══════════════════▼════════╗
  ║  APPLICATION LAYER  (Python Flask + Gunicorn)                                ║
  ║                                                                              ║
  ║  /health  /ready  /metrics  /login  /load  /memory  /exec  /probe           ║
  ║                                                                              ║
  ║  UID 1001 │ ReadOnlyRootFS │ No SA token │ Drop ALL caps │ Seccomp          ║
  ║  Prometheus metrics client → Counter, Gauge, Histogram                       ║
  ║  Structured JSON logs → stdout → captured by Promtail                       ║
  ╚══════════════════════════════╤═══════════════════════════════════════════════╝
                                 │
              ┌──────────────────┴──────────────────┐
              │                                     │
  ╔═══════════▼═══════════════╗       ╔═════════════▼═════════════╗
  ║   METRICS PIPELINE        ║       ║   LOGGING PIPELINE        ║
  ║                           ║       ║                           ║
  ║  ┌─────────────────────┐  ║       ║  ┌─────────────────────┐  ║
  ║  │     Prometheus      │  ║       ║  │      Promtail       │  ║
  ║  │  Scrapes /metrics   │  ║       ║  │  DaemonSet per node │  ║
  ║  │  every 15 seconds   │  ║       ║  │  Pipeline stages    │  ║
  ║  │  15-day retention   │  ║       ║  │  Drop probe noise   │  ║
  ║  └──────────┬──────────┘  ║       ║  └──────────┬──────────┘  ║
  ║             │ Evaluates   ║       ║             │ Ships to    ║
  ║             │ 12 rules    ║       ║  ┌──────────▼──────────┐  ║
  ║  ┌──────────▼──────────┐  ║       ║  │       Loki          │  ║
  ║  │    Alertmanager     │  ║       ║  │  Label-indexed logs │  ║
  ║  │  Routing by         │◄─╫───────╫──│  4 LogQL alert rules│  ║
  ║  │  severity + team    │  ║       ║  │  30-day retention   │  ║
  ║  │  Dedup + Inhibition │  ║       ║  └─────────────────────┘  ║
  ║  └──────────┬──────────┘  ║       ╚═══════════════════════════╝
  ╚═════════════╪═════════════╝
                │
  ╔═════════════▼═══════════════════════════════════════════════════════════════╗
  ║  NOTIFICATION LAYER                                                         ║
  ║  ┌─────────────────┐   ┌──────────────────┐   ┌───────────────────────┐   ║
  ║  │  Slack Webhook  │   │  PagerDuty       │   │  Email (SMTP)         │   ║
  ║  │  #sec-incidents │   │  Critical pages  │   │  Email (configurable) │   ║
  ║  │  #platform-ops  │   │  30min re-alert  │   │  HTML template        │   ║
  ║  └─────────────────┘   └──────────────────┘   └───────────────────────┘   ║
  ╚═════════════════════════════════════════════════════════════════════════════╝

  ╔═════════════════════════════════════════════════════════════════════════════╗
  ║  RUNTIME SECURITY LAYER  ──  Falco eBPF Syscall Interception               ║
  ║                                                                             ║
  ║  Every node │ Every container │ Every syscall                              ║
  ║                                                                             ║
  ║  exec()        →  shell_spawned_in_container         (T1059.004) CRITICAL  ║
  ║  connect()     →  unexpected_outbound_connection     (T1071)     HIGH      ║
  ║  open(WRITE)   →  write_sensitive_file               (T1222)     CRITICAL  ║
  ║  setuid()      →  privilege_escalation_attempt       (T1068)     CRITICAL  ║
  ║  open(/proc)   →  proc_filesystem_access             (T1057)     CRITICAL  ║
  ║                                                                             ║
  ║  Falco → Falcosidekick → Alertmanager + Loki + Slack                      ║
  ╚═════════════════════════════════════════════════════════════════════════════╝

  ╔═════════════════════════════════════════════════════════════════════════════╗
  ║  ENFORCEMENT LAYER                                                          ║
  ║  ┌──────────────────────┐  ┌─────────────────────┐  ┌──────────────────┐  ║
  ║  │   NetworkPolicy      │  │   ResourceQuota      │  │  Pod Security    │  ║
  ║  │   Default deny all   │  │   4 CPU / 4Gi hard   │  │  Admission       │  ║
  ║  │   8 allowlist rules  │  │   20 pod limit       │  │  restricted      │  ║
  ║  │   Zero-trust east-   │  │   No LoadBalancer    │  │  profile enforced│  ║
  ║  │   west traffic       │  │   No NodePort        │  │  on namespace    │  ║
  ║  └──────────────────────┘  └─────────────────────┘  └──────────────────┘  ║
  ╚═════════════════════════════════════════════════════════════════════════════╝
```

---

## Detection Flow

```
  ATTACK OCCURS
       │
       ▼
  ──────────────────────────────────────────────────────────────
  LAYER 1 │ METRIC SIGNAL                             ~15-30s
  ──────────────────────────────────────────────────────────────
  Flask Prometheus client increments counter
  failed_logins_total{source_ip="x.x.x.x"} += 1
  Prometheus scrapes /metrics every 15s
  Alert rule evaluates: rate(failed_logins_total[2m]) > 10
  PENDING → FIRING after `for:` duration
       │
       ▼
  ──────────────────────────────────────────────────────────────
  LAYER 2 │ LOG SIGNAL                                ~5-15s
  ──────────────────────────────────────────────────────────────
  Structured log emitted:
    AUTHENTICATION_FAILURE user=admin source_ip=x.x.x.x
  Promtail pipeline extracts label: event_type=AUTHENTICATION_FAILURE
  Loki ingests log stream with labels
  LogQL rule fires: count_over_time > threshold
  Loki ruler → Alertmanager → second correlated alert
       │
       ▼
  ──────────────────────────────────────────────────────────────
  LAYER 3 │ RUNTIME SIGNAL (exec/file/network)        ~< 1s
  ──────────────────────────────────────────────────────────────
  eBPF probe intercepts exec() syscall
  Falco matches rule: shell_spawned_in_container
  Falcosidekick fans out to Alertmanager + Loki + Slack
  Correlation: same pod, overlapping time window
       │
       ▼
  ──────────────────────────────────────────────────────────────
  RESPONSE │ SOC ACTION
  ──────────────────────────────────────────────────────────────
  Analyst receives Slack alert with direct playbook link
  Opens Grafana: correlates metrics + logs + Falco events
  Executes playbook: isolate → preserve evidence → eradicate
  MTTC target: 15 minutes from first alert
```

---

## Repository Structure

```
cloud-threat-detection/
│
├── 📦 app/
│   ├── app.py                      # Flask app — 10 endpoints, Prometheus metrics, attack surfaces
│   └── requirements.txt            # Pinned Python dependencies
│
├── 🐳 docker/
│   ├── Dockerfile                  # Multi-stage build, UID 1001, readOnlyRootFS, health checks
│   └── .dockerignore
│
├── ☸️  k8s/
│   ├── namespace.yaml              # PSA restricted enforcement
│   ├── serviceaccount.yaml         # No API token mounted
│   ├── configmap.yaml
│   ├── deployment.yaml             # Full securityContext, probes, resource limits
│   ├── service.yaml                # ClusterIP only (no external exposure)
│   ├── network-policy.yaml         # Default-deny + 8 allowlist rules
│   └── resource-quota.yaml         # Namespace CPU/memory/object caps
│
├── 📊 monitoring/
│   ├── prometheus/
│   │   ├── prometheus-config.yaml  # Scrape configs, pod discovery, self-monitoring
│   │   ├── alert-rules.yaml        # 12 production alert rules across 6 groups
│   │   └── prometheus-deployment.yaml
│   │
│   ├── alertmanager/
│   │   ├── alertmanager-config.yaml    # Routing tree, receivers, inhibition rules
│   │   └── alertmanager-deployment.yaml # Webhook simulator included
│   │
│   ├── loki/
│   │   ├── loki-config.yaml        # Loki + 4 LogQL alert rules
│   │   └── loki-deployment.yaml    # Loki StatefulSet + Promtail DaemonSet
│   │
│   ├── falco/
│   │   ├── falco-rules.yaml        # 9 custom rules with MITRE ATT&CK mapping
│   │   └── falco-deployment.yaml   # DaemonSet + Falcosidekick + RBAC
│   │
│   └── grafana/
│       └── grafana-deployment.yaml # Datasource provisioning (Prometheus + Loki)
│
├── 💥 attacks/
│   ├── brute_force.py              # Sequential + distributed credential stuffing
│   ├── cpu_spike.py                # CPU exhaustion with alert monitoring
│   ├── memory_exhaustion.py        # Escalating memory pressure + OOM simulation
│   └── suspicious_commands.py      # Full kill chain: recon → persistence → C2
│
├── 📋 docs/
│   ├── incident-playbook-brute-force.md    # SEC-001 with forensic queries + containment
│   ├── incident-playbook-container-compromise.md  # SEC-002 with 15min MTTC target
│   └── threat-model.md             # STRIDE + MITRE ATT&CK for Containers
│
├── docker-compose.yaml             # Local dev stack (no K8s required)
├── Makefile                        # deploy / attack / port-forward / verify targets
└── README.md
```

---

## Quick Start

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| `kubectl` | 1.28+ | Cluster management |
| `helm` | 3.x | Falco deployment |
| `python3` | 3.10+ | Attack simulation scripts |
| `docker` | 24+ | Image build |
| CNI | Calico / Cilium | NetworkPolicy enforcement |

### Option A — Full Kubernetes Deployment

```bash
# 1. Clone
git clone https://github.com/codewithbrandon/cloud-threat-detection.git
cd cloud-threat-detection

# 2. Deploy everything with make
make deploy              # namespace + monitoring + app + network policies
make deploy-falco        # Falco via Helm (requires Linux node for eBPF)

# 3. Access dashboards
make port-forward

# 4. Verify the stack is healthy
make verify
```

### Option B — Local Docker Compose (no K8s required)

```bash
# Start full monitoring stack locally
docker-compose up -d

# Verify all containers running
docker-compose ps

# View app logs
docker-compose logs -f app
```

### Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://localhost:3000 | anonymous viewer |
| Prometheus | http://localhost:9090 | none |
| Alertmanager | http://localhost:9093 | none |
| Application | http://localhost:8080 | — |

---

## Simulating Attacks

> All scripts are safe — they target the local application only and generate
> the syscall/log/metric patterns that detection rules look for.

### Brute Force Login — `T1110`

```bash
# Sequential: single IP rapid fire (tests per-IP Prometheus threshold)
python3 attacks/brute_force.py \
  --target http://localhost:8080 \
  --mode sequential --count 25 --rate 5

# Distributed: multiple IPs (tests global Loki LogQL threshold)
python3 attacks/brute_force.py \
  --target http://localhost:8080 \
  --mode distributed --count 60 --concurrency 4
```

**Fires:** `ExcessiveFailedLogins` → `BruteForceAttackCritical` → `BruteForceInLogs`

**Verify:**
```bash
# Prometheus
curl -s http://localhost:9090/api/v1/query \
  --data 'query=sum(increase(failed_logins_total[2m]))by(source_ip)'

# Loki (in Grafana Explore)
{app="threat-detection-app"} |= "AUTHENTICATION_FAILURE" | json
```

---

### CPU Spike — `T1499`

```bash
python3 attacks/cpu_spike.py \
  --target http://localhost:8080 \
  --intensity 0.9 --duration 120
```

**Fires:** `HighCPUUsage` (>75% for 2min) → `CriticalCPUSpike` (>95% for 1min)

---

### Memory Exhaustion — `T1499.004`

```bash
# Gradual escalation across 4 steps to 480MB (limit: 512MB)
python3 attacks/memory_exhaustion.py \
  --target http://localhost:8080 \
  --mode escalating --size 480 --steps 4 --hold 30
```

**Fires:** `HighMemoryUsage` → `MemoryExhaustionCritical` → Kubernetes OOM kill → `PodCrashLoopDetected`

---

### Full Kill Chain — `T1059 → T1057 → T1222 → T1071`

```bash
# Runs: recon → network discovery → persistence → C2 beaconing
python3 attacks/suspicious_commands.py \
  --target http://localhost:8080 \
  --scenario kill-chain
```

**Fires:** Falco `shell_spawned_in_container` + `unexpected_outbound_connection` + `write_sensitive_file`

```bash
# Watch Falco alerts in real-time
kubectl logs -n threat-detection -l app=falco -f | \
  jq '{rule: .rule, priority: .priority, pod: .output_fields."k8s.pod.name"}'
```

---

### Run Everything

```bash
make attack-all
```

---

## Alert Reference

<table>
<thead>
<tr>
<th>Alert</th>
<th>Trigger</th>
<th>Severity</th>
<th>Channel</th>
<th>Response SLA</th>
</tr>
</thead>
<tbody>
<tr><td><code>ExcessiveFailedLogins</code></td><td>>10 failures/2min/IP</td><td>⚠️ WARNING</td><td>#security-alerts</td><td>5 min</td></tr>
<tr><td><code>BruteForceAttackCritical</code></td><td>>50 failures/1min/IP</td><td>🔴 CRITICAL</td><td>#security-incidents + page</td><td>Immediate</td></tr>
<tr><td><code>HighCPUUsage</code></td><td>CPU >75% for 2min</td><td>⚠️ WARNING</td><td>#platform-alerts</td><td>15 min</td></tr>
<tr><td><code>CriticalCPUSpike</code></td><td>CPU >95% for 1min</td><td>🔴 CRITICAL</td><td>#platform-oncall + page</td><td>5 min</td></tr>
<tr><td><code>HighMemoryUsage</code></td><td>Memory >384Mi for 2min</td><td>⚠️ WARNING</td><td>#platform-alerts</td><td>15 min</td></tr>
<tr><td><code>MemoryExhaustionCritical</code></td><td>Memory >460Mi</td><td>🔴 CRITICAL</td><td>#platform-oncall + page</td><td>5 min</td></tr>
<tr><td><code>High5xxErrorRate</code></td><td>5xx >5% for 2min</td><td>⚠️ WARNING</td><td>#platform-alerts</td><td>15 min</td></tr>
<tr><td><code>ServiceUnavailable</code></td><td>5xx >50% for 1min</td><td>🔴 CRITICAL</td><td>#platform-oncall + page</td><td>5 min</td></tr>
<tr><td><code>PodCrashLoopDetected</code></td><td>>3 restarts / 15min</td><td>🔴 CRITICAL</td><td>#platform-oncall + page</td><td>5 min</td></tr>
<tr><td><code>SuspiciousActivityDetected</code></td><td>suspicious_activity_total > 0</td><td>⚠️ WARNING</td><td>#security-alerts</td><td>10 min</td></tr>
<tr><td><code>PrometheusTargetDown</code></td><td>Scrape target down 2min</td><td>🔴 CRITICAL</td><td>#platform-oncall</td><td>5 min</td></tr>
<tr><td><code>WatchdogHeartbeat</code></td><td>Always firing (dead man's switch)</td><td>🔵 NONE</td><td>External monitor</td><td>N/A</td></tr>
</tbody>
</table>

---

## Falco Runtime Rules

<table>
<thead>
<tr>
<th>Rule</th>
<th>Syscall Trigger</th>
<th>MITRE Technique</th>
<th>Priority</th>
</tr>
</thead>
<tbody>
<tr><td><code>shell_spawned_in_container</code></td><td>exec() → sh/bash/zsh</td><td>T1059.004</td><td>🔴 CRITICAL</td></tr>
<tr><td><code>unexpected_outbound_connection</code></td><td>connect() to non-whitelisted IP</td><td>T1071</td><td>🟠 HIGH</td></tr>
<tr><td><code>write_sensitive_file</code></td><td>open(WRITE) on /etc, /bin, /usr</td><td>T1222</td><td>🔴 CRITICAL</td></tr>
<tr><td><code>dangerous_binary_in_container</code></td><td>exec() → wget, curl, nc, nmap</td><td>T1105</td><td>🟠 HIGH</td></tr>
<tr><td><code>container_running_as_root</code></td><td>spawned_process, UID=0</td><td>T1078</td><td>🟠 HIGH</td></tr>
<tr><td><code>proc_filesystem_access</code></td><td>open() on /proc/1, /proc/kcore</td><td>T1057</td><td>🔴 CRITICAL</td></tr>
<tr><td><code>crypto_miner_detected</code></td><td>exec() → xmrig, stratum+tcp</td><td>T1496</td><td>🔴 CRITICAL</td></tr>
<tr><td><code>k8s_secret_access_in_container</code></td><td>open() on /var/run/secrets</td><td>T1552</td><td>🔴 CRITICAL</td></tr>
<tr><td><code>privilege_escalation_attempt</code></td><td>setuid()/setgid() succeeds</td><td>T1068</td><td>🔴 CRITICAL</td></tr>
</tbody>
</table>

---

## Security Controls

```
Container Layer
  ✅  Non-root user (UID 1001)           ✅  Read-only root filesystem
  ✅  No privilege escalation            ✅  Drop ALL Linux capabilities
  ✅  Seccomp RuntimeDefault profile     ✅  Multi-stage minimal image

Pod Layer
  ✅  No ServiceAccount token mounted    ✅  Dedicated ServiceAccount
  ✅  Pod Security Admission: restricted ✅  Topology spread constraints
  ✅  Resource limits (CPU + memory)     ✅  Liveness + readiness + startup probes

Namespace Layer
  ✅  Default-deny NetworkPolicy         ✅  8 explicit allowlist rules
  ✅  ResourceQuota (CPU/mem/objects)    ✅  LimitRange (per-container defaults)
  ✅  No LoadBalancer services           ✅  No NodePort services

Runtime Layer
  ✅  Falco eBPF syscall monitoring      ✅  9 custom rules (MITRE-mapped)
  ✅  Falcosidekick fan-out routing      ✅  12 Prometheus alert rules
  ✅  4 LogQL log-based alert rules      ✅  Dead man's switch heartbeat
  ✅  Alert deduplication + inhibition   ✅  Multi-channel notification
```

---

## MITRE ATT&CK Coverage

| Tactic | Techniques Covered | Detection Layer |
|--------|-------------------|-----------------|
| Initial Access | T1190 Exploit Public-Facing App | Loki + Falco |
| Execution | T1059.004 Unix Shell | Falco (exec syscall) |
| Persistence | T1222 File Permissions Modification | Falco (open syscall) |
| Privilege Escalation | T1068, T1611 Container Escape | Falco (setuid syscall) |
| Defense Evasion | T1070 Indicator Removal | Falco (readOnlyFS blocks) |
| Credential Access | T1552 Unsecured Credentials, T1110 Brute Force | Prometheus + Loki + Falco |
| Discovery | T1057 Process Discovery | Falco (exec syscall) |
| Lateral Movement | T1210 Exploitation of Remote Services | Falco + NetworkPolicy |
| Command & Control | T1071 Application Layer Protocol | Falco + NetworkPolicy |
| Exfiltration | T1041 Exfiltration Over C2 Channel | Falco + NetworkPolicy |
| Impact | T1496 Resource Hijacking, T1499 Endpoint DoS | Prometheus |

---

## Incident Playbooks

| Playbook | Scenario | Trigger | MTTC Target |
|----------|----------|---------|-------------|
| [SEC-001](docs/incident-playbook-brute-force.md) | Brute Force / Credential Stuffing | `BruteForceAttackCritical` | N/A (alerting + block) |
| [SEC-002](docs/incident-playbook-container-compromise.md) | Container Compromise / Runtime Attack | `shell_spawned_in_container` | **15 minutes** |

Each playbook includes:
- Detection signal inventory
- Incident timeline template
- Triage decision tree
- Step-by-step containment commands
- Forensic evidence collection (before pod termination)
- Loki / Prometheus investigation queries
- Eradication and recovery procedures
- Lessons learned template

---

## Interview Talking Points

<details>
<summary><strong>Walk me through your detection stack</strong></summary>

The platform has three independent detection layers. Prometheus pulls metrics every 15 seconds — I alert on `failed_logins_total` crossing 10/2min per IP, which catches brute force. Loki aggregates structured logs from Promtail with pipeline stages that extract `event_type` labels — I use LogQL `count_over_time` rules for distributed attacks that stay below per-IP thresholds. Falco intercepts eBPF syscalls — `exec()`, `connect()`, and `open()` — which catches post-compromise behavior that metrics and logs miss entirely. All three feed Alertmanager which groups, deduplicates, and routes to Slack, PagerDuty, and email by severity.

</details>

<details>
<summary><strong>How do you handle alert fatigue?</strong></summary>

Three mechanisms. First, Alertmanager inhibition rules suppress warning-level alerts when a critical on the same incident is already firing — `BruteForceAttackCritical` inhibits `ExcessiveFailedLogins`. Second, grouping batches related alerts into one notification instead of 50. Third, the `drop` pipeline stage in Promtail filters `/health`, `/ready`, and `/metrics` scrape logs before ingestion — Loki alert queries don't generate noise from expected traffic patterns.

</details>

<details>
<summary><strong>What would you add if this were production?</strong></summary>

Three things immediately. Istio or Cilium for mTLS between pods — right now NetworkPolicy provides network-level isolation but no identity-based encryption. Image signing with Cosign and an admission webhook to reject unsigned images — this closes the supply chain gap in my STRIDE threat model. Third, Kubernetes audit log shipping to Loki — right now I detect container behavior but not API server operations like unusual RBAC changes or secret access patterns.

</details>

<details>
<summary><strong>How do you prove this actually works?</strong></summary>

The attack simulation scripts are the test suite. `brute_force.py` triggers `ExcessiveFailedLogins` and I time from first request to Slack notification — SLA is 2 minutes, actual is typically 35-45 seconds. `suspicious_commands.py` triggers all three Falco rules and I verify each appears in Falco pod logs and Alertmanager within 10 seconds. The dead man's switch `WatchdogHeartbeat` alert validates that the entire alerting pipeline is functional — if it stops firing, we have a bigger problem than any individual alert.

</details>

<details>
<summary><strong>Why Loki over Elasticsearch?</strong></summary>

Loki is label-indexed, not full-text indexed. For security use cases, I know exactly what I'm searching for — specific event types, pod names, source IPs. Loki's structured label queries are orders of magnitude cheaper at scale. It integrates natively with Prometheus labels, enabling metric-to-log correlation in Grafana without context switching. Storage cost is roughly 90% lower than Elasticsearch at equivalent log volume.

</details>

<details>
<summary><strong>Why do you use three detection layers instead of one?</strong></summary>

Defense in depth. An attacker who compromises the application and stops writing logs still generates syscalls that Falco catches. An attack that stays below per-IP metric thresholds still shows up in global Loki log counts. A Falco rule gap doesn't mean the attack is invisible — Prometheus captures the metric signal. Each layer has different blind spots; combining them means an attacker has to evade all three simultaneously, which is exponentially harder.

</details>

---

## Quality Gates

Every push and pull request runs the full CI pipeline:

| Check | Tool | What It Catches |
|-------|------|-----------------|
| YAML lint | `yamllint` | Indentation, trailing spaces, type errors in all manifests |
| K8s schema validation | `kubeconform` | Invalid Kubernetes API fields against the 1.29 schema |
| Python lint | `ruff` | Import order, unused vars, style, pyupgrade suggestions |
| Python format | `black` | Consistent code formatting — fails on drift |
| Secret scanning | `gitleaks` | Accidentally committed keys, tokens, passwords |
| Container CVE scan | `trivy` (image) | OS + library CVEs in the built Docker image (fails on CRITICAL) |
| Filesystem scan | `trivy` (fs) | IaC misconfigurations and secrets in source (informational) |

Results from Trivy appear in the [GitHub Security tab](https://github.com/codewithbrandon/cloud-threat-detection/security).

### Run checks locally

```bash
# Install tools once
pip install ruff==0.4.10 black==24.4.2 yamllint==1.35.1

# Install kubeconform (Linux/macOS)
curl -sSL https://github.com/yannh/kubeconform/releases/download/v0.6.7/kubeconform-linux-amd64.tar.gz \
  | tar -xz -C /usr/local/bin kubeconform

# Run all checks
make lint           # yaml + python

make validate-k8s   # kubeconform schema validation

make lint-fix       # auto-fix python formatting (writes files)
```

---

## Threat Model

Full STRIDE analysis with risk register → [docs/threat-model.md](docs/threat-model.md)

**Highest residual risks (by design decision):**
- Supply chain compromise — mitigated by pinned base image digests; Cosign signing is the next control
- Distributed brute force below per-IP threshold — mitigated by global Loki rule; WAF is the next control
- Falco rule gap — mitigated by metric + log parallel detection; continuous rule testing is the process control

---

<div align="center">

---

**Built to solve real gaps in container runtime visibility.**
*Detection without response is expensive logging. This platform connects both.*

<br/>

[![Star this repo](https://img.shields.io/github/stars/codewithbrandon/cloud-threat-detection?style=social)](https://github.com/codewithbrandon/cloud-threat-detection)

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f0c29,50:302b63,100:24243e&height=100&section=footer" width="100%"/>

</div>
