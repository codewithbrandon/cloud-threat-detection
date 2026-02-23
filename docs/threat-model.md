# Threat Model — Cloud-Native Threat Detection Platform

**Version:** 1.0
**Methodology:** STRIDE + MITRE ATT&CK for Containers
**Last Updated:** 2024-01-01

---

## System Overview

The platform is a Kubernetes-hosted monitoring system. It has three user-facing boundaries: the Flask application (HTTP), the Prometheus metrics API, and the Grafana dashboard. All other components are internal-only.

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  EXTERNAL (Untrusted)                                       │
│  ┌───────────────┐  ┌─────────────────┐                    │
│  │  Attack       │  │  Synthetic       │                    │
│  │  Simulator    │  │  Traffic Gen     │                    │
│  └───────┬───────┘  └────────┬────────┘                    │
└──────────┼───────────────────┼─────────────────────────────┘
           │ HTTP (Port 8080)  │
┌──────────▼───────────────────▼─────────────────────────────┐
│  KUBERNETES NAMESPACE (threat-detection)                    │
│                                                             │
│  ┌─────────────────────────┐                               │
│  │  Flask App              │  ← Application Trust Zone     │
│  │  UID 1001 (non-root)    │                               │
│  │  ReadOnlyRootFilesystem │                               │
│  │  No SA token mounted    │                               │
│  └────────────┬────────────┘                               │
│               │                                             │
│  ┌────────────▼────────────┐  ┌────────────────────────┐  │
│  │  Prometheus             │  │  Loki + Promtail        │  │
│  │  (Monitoring Zone)      │  │  (Logging Zone)         │  │
│  └────────────┬────────────┘  └────────────┬───────────┘  │
│               │                              │              │
│  ┌────────────▼──────────────────────────────▼───────────┐ │
│  │  Alertmanager          Falco + Falcosidekick           │ │
│  │  (Alert Routing)       (Runtime Security Zone)         │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────┐
│  KUBERNETES CONTROL PLANE (Highly Privileged)               │
│  API Server | etcd | kubelet | kube-scheduler               │
└─────────────────────────────────────────────────────────────┘
```

---

## STRIDE Threat Analysis

### S — Spoofing

| Threat | Target | Controls | Residual Risk |
|--------|--------|----------|---------------|
| Attacker spoofs source IP in login attempts | /login endpoint | X-Forwarded-For tracking; NetworkPolicy | Medium — IP spoofing possible in some CNI configs |
| Attacker spoofs Prometheus scrape request | /metrics endpoint | ClusterIP-only service; NetworkPolicy allow-prometheus-scrape | Low |
| Attacker impersonates Kubernetes SA | K8s API Server | automountServiceAccountToken: false | Low |
| Rogue pod claims app label to receive traffic | Service selector | Pod labels not authenticated; use NetworkPolicy | Medium |

**Mitigations:**
- Mutual TLS (mTLS) between services (Istio/Linkerd) would reduce IP spoofing risk
- Service mesh identity (SPIFFE/SPIRE) for pod authentication

---

### T — Tampering

| Threat | Target | Controls | Residual Risk |
|--------|--------|----------|---------------|
| Attacker modifies container filesystem | Container FS | readOnlyRootFilesystem: true | Low — Falco alerts on any write attempt |
| Attacker modifies Prometheus rules | Alert ConfigMap | RBAC (no write to ConfigMaps from app) | Low |
| Supply chain: malicious base image | Docker image | Pin base image digest; Trivy scan in CI | Medium — requires CI/CD security |
| Attacker modifies etcd (Prometheus data) | Prometheus TSDB | PVC access control; node-level security | Low |

---

### R — Repudiation

| Threat | Target | Controls | Residual Risk |
|--------|--------|----------|---------------|
| Attacker denies authentication attempts | /login | Structured log with timestamp, IP, username → Loki (immutable) | Low |
| Pod actions not attributed to source | Container | Falco captures UID, cmdline, container name | Low |
| Alert routing failure — no notification record | Alertmanager | Alertmanager internal log; webhook simulator | Medium |

**Mitigations:**
- Ship logs to write-once storage (S3 with Object Lock) for forensic admissibility
- Kubernetes audit logging to external SIEM

---

### I — Information Disclosure

| Threat | Target | Controls | Residual Risk |
|--------|--------|----------|---------------|
| Attacker reads /metrics endpoint | Prometheus metrics | ClusterIP only; NetworkPolicy | Low |
| Attacker reads environment variables | Container env | ConfigMap (not Secret) for config; no secrets in env | Low |
| Attacker reads other pods' logs via Promtail | Loki | Promtail reads all ns logs (by design) | Medium — necessary exception |
| Container escape exposes host processes | Host | seccompProfile: RuntimeDefault; non-root; no hostPID | Low |

---

### D — Denial of Service

| Threat | Target | Controls | Residual Risk |
|--------|--------|----------|---------------|
| CPU exhaustion via /load endpoint | Pod | Resource limits (500m CPU); HPA | Medium — pod degraded but not killed |
| Memory exhaustion via /memory endpoint | Pod | Resource limits (512Mi); OOM kill; alert | Medium — OOM kill causes restart |
| Pod restart loop (crash loop) | Service | PodCrashLoopDetected alert; HPA | Medium |
| Prometheus storage exhaustion | TSDB | 8GB storage limit; 15-day retention | Low |
| Alert storm via scrape target manipulation | Alertmanager | Alert grouping; inhibition rules | Low |

**Priority Mitigations:**
- Rate limit /load and /memory endpoints at ingress controller
- Implement HPA to absorb load spikes
- Use Kubernetes PodDisruptionBudget for availability guarantees

---

### E — Elevation of Privilege

| Threat | Target | Controls | Residual Risk |
|--------|--------|----------|---------------|
| Container escapes to host via kernel exploit | Host kernel | seccomp; non-root; no capabilities | Low — mitigated, not eliminated |
| setuid binary privilege escalation | Container | allowPrivilegeEscalation: false; capabilities: drop ALL | Very Low |
| Kubernetes SA token enables API access | K8s API | automountServiceAccountToken: false | Very Low |
| Falco pod abuse (runs privileged) | Cluster | Falco SA limited to read-only; separate namespace | Medium — inherent risk of runtime monitoring |

---

## MITRE ATT&CK for Containers — Coverage Map

| Tactic | Technique | Simulation | Detection |
|--------|-----------|------------|-----------|
| Initial Access | T1190 Exploit Public App | /exec endpoint | Falco + Loki |
| Execution | T1059.004 Unix Shell | /exec endpoint | Falco: shell_spawned |
| Persistence | T1222 File Permissions | /file-write | Falco: write_sensitive |
| Privilege Escalation | T1611 Container Escape | seccomp test | Falco: proc_fs_access |
| Defense Evasion | T1070 Log Deletion | readOnlyRootFS blocks | Falco |
| Credential Access | T1552 Unsecured Creds | /exec env_list | Falco + Loki |
| Discovery | T1057 Process Discovery | /exec ps | Falco: dangerous_binary |
| Lateral Movement | T1210 Exploit Remote Services | /probe endpoint | Falco: unexpected_egress |
| Collection | T1005 Local Data Staging | /file-write | Falco |
| Command & Control | T1071 App Layer Protocol | /probe + NetworkPolicy | Falco + NetworkPolicy |
| Exfiltration | T1041 Exfil Over C2 | /probe to external IP | Falco + NetworkPolicy |
| Impact | T1496 Resource Hijacking | /load endpoint | Prometheus HighCPU |
| Impact | T1499 Endpoint DoS | /memory endpoint | Prometheus HighMemory |
| Credential Access | T1110 Brute Force | brute_force.py | Prometheus + Loki |

---

## Risk Register

| Risk ID | Risk Description | Likelihood | Impact | Score | Mitigation |
|---------|-----------------|------------|--------|-------|------------|
| R-001 | Container escape via kernel CVE | Low | Critical | 8/20 | Patch nodes; seccomp; gVisor |
| R-002 | Supply chain compromise | Medium | Critical | 12/20 | Image signing; Trivy in CI |
| R-003 | Prometheus data tampering | Low | High | 6/20 | RBAC; PVC access control |
| R-004 | Distributed brute force below per-IP threshold | Medium | High | 8/20 | Global rate limit; WAF |
| R-005 | Falco false negative (rule gap) | Medium | High | 8/20 | Rule testing; coverage matrix |
| R-006 | Alert routing failure | Low | Critical | 8/20 | Dead man's switch; multi-channel |
| R-007 | Log tampering via Promtail access | Low | High | 6/20 | Immutable log storage |
| R-008 | Network policy bypass (CNI bug) | Very Low | Critical | 4/20 | Multiple CNI layers; Istio |

---

## Security Assumptions

1. The Kubernetes control plane is trusted and secured (this platform does not model control plane threats)
2. Node-level host security is enforced (CIS Kubernetes Benchmark applied to nodes)
3. Container images are built from trusted base images with Trivy scanning in CI/CD
4. NetworkPolicy enforcement is provided by a compliant CNI (Calico or Cilium)
5. Falco has unobstructed access to host syscalls via eBPF

---

*Threat model owner: Platform Security Team | Review cycle: Quarterly*
