# Incident Playbook: Brute Force / Credential Stuffing Attack

**Playbook ID:** SEC-001
**Severity:** HIGH → CRITICAL (escalates with sustained volume)
**Owner:** Security Operations (SOC)
**Review Cycle:** Quarterly

---

## Overview

A brute force or credential stuffing attack generates a high volume of failed authentication attempts against the `/login` endpoint. This playbook covers detection, triage, containment, eradication, and post-incident review.

**MITRE ATT&CK:**
- T1110 — Brute Force
- T1110.004 — Credential Stuffing
- T1078 — Valid Accounts (if successful)

---

## Detection Signals

The following alerts indicate a brute force attack in progress:

| Signal | Source | Threshold | Severity |
|--------|--------|-----------|----------|
| `ExcessiveFailedLogins` | Prometheus | >10 failures/2min per IP | WARNING |
| `BruteForceAttackCritical` | Prometheus | >50 failures/1min per IP | CRITICAL |
| `BruteForceInLogs` | Loki LogQL | >20 failures/1min global | WARNING |
| `BRUTE_FORCE_DETECTED` log line | Loki | Any occurrence | HIGH |
| `suspicious_activity_total{activity_type="brute_force_attempt"}` | Prometheus | >0 | WARNING |

### Sample Alert Payload (Alertmanager → Slack)

```json
{
  "alertname": "BruteForceAttackCritical",
  "severity": "critical",
  "source_ip": "203.0.113.10",
  "description": "ACTIVE ATTACK: 78 failed logins in 1 minute from 203.0.113.10",
  "playbook": "docs/incident-playbook-brute-force.md"
}
```

---

## Incident Timeline Template

```
[T+0:00]  Alert fires: ExcessiveFailedLogins from 203.0.113.10
[T+0:05]  SOC acknowledges alert in Alertmanager
[T+0:10]  Triage begins — Loki query to assess scope
[T+0:15]  Source IP blocked via NetworkPolicy patch
[T+0:20]  Loki query confirms no successful logins during attack window
[T+0:30]  CISO/manager notified if active attack continues
[T+1:00]  Post-incident review initiated
[T+24:00] RCA document completed
```

---

## Detection Verification

Before taking action, confirm the alert is a true positive:

```bash
# 1. Query Loki for authentication failures in the last 30 minutes
{app="threat-detection-app"} |= "AUTHENTICATION_FAILURE" | json
  | line_format "{{.timestamp}} user={{.username}} ip={{.source_ip}}"

# 2. Count failures by source IP
sum by (source_ip) (
  count_over_time({app="threat-detection-app"} |= "AUTHENTICATION_FAILURE" [30m])
)

# 3. Check if any login succeeded during attack window
{app="threat-detection-app"} |= "AUTHENTICATION_SUCCESS"
  | json | line_format "{{.timestamp}} user={{.username}} ip={{.source_ip}}"

# 4. Check Prometheus metric directly
curl http://prometheus:9090/api/v1/query \
  --data 'query=sum(increase(failed_logins_total[5m])) by (source_ip)'
```

---

## Triage Decision Tree

```
Alert: ExcessiveFailedLogins
         │
         ▼
 Is source IP external?
    ├── YES → Is it a known scanner/pentest IP?
    │           ├── YES → Acknowledge, no action, document
    │           └── NO  → [CONTAINMENT STEP 1]
    └── NO  → Is it an internal service IP?
                ├── YES → Investigate service misconfiguration
                └── NO  → [CONTAINMENT STEP 1] + Escalate
                          (potential insider threat)

Did any login succeed?
    ├── YES → [CRITICAL] → Incident declared, full investigation
    └── NO  → Continue monitoring, apply rate limiting
```

---

## Containment Procedures

### Step 1: Block Source IP via NetworkPolicy

```bash
# Get current NetworkPolicy
kubectl get networkpolicy -n threat-detection

# Patch to add deny rule for attacker IP (example: 203.0.113.10)
# Note: Standard NetworkPolicy doesn't support IP deny — use Calico/Cilium GlobalNetworkPolicy

# Option A: Calico GlobalNetworkPolicy (if using Calico CNI)
cat <<EOF | kubectl apply -f -
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: block-brute-force-source
spec:
  selector: all()
  order: 1
  types:
    - Ingress
  ingress:
    - action: Deny
      source:
        nets:
          - 203.0.113.10/32
EOF

# Option B: Cilium NetworkPolicy (if using Cilium CNI)
cat <<EOF | kubectl apply -f -
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: block-brute-force-source
  namespace: threat-detection
spec:
  endpointSelector:
    matchLabels:
      app: threat-detection-app
  ingressDeny:
    - fromCIDRSet:
        - cidr: 203.0.113.10/32
EOF
```

### Step 2: Enable Alertmanager Silence (reduce alert noise)

```bash
# Create silence for ExcessiveFailedLogins while investigating
# (BruteForceAttackCritical should NOT be silenced)
curl -X POST http://alertmanager:9093/api/v1/silences \
  -H 'Content-Type: application/json' \
  -d '{
    "matchers": [
      {"name": "alertname", "value": "ExcessiveFailedLogins", "isRegex": false},
      {"name": "source_ip", "value": "203.0.113.10", "isRegex": false}
    ],
    "startsAt": "2024-01-01T00:00:00Z",
    "endsAt": "2024-01-01T02:00:00Z",
    "comment": "Investigating brute force from 203.0.113.10 — SEC-001",
    "createdBy": "soc-analyst"
  }'
```

### Step 3: Isolate Affected Pod (if compromise suspected)

```bash
# If any login succeeded — isolate the pod immediately
# Add restrictive NetworkPolicy to cut all ingress/egress
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-compromised-pod
  namespace: threat-detection
spec:
  podSelector:
    matchLabels:
      app: threat-detection-app
  policyTypes:
    - Ingress
    - Egress
  # No rules = deny all
EOF

# Cordon the node to prevent new pod scheduling there
kubectl cordon <node-name>
```

---

## Investigation Queries

### Loki — Full authentication log analysis

```logql
# All auth events for a specific source IP
{app="threat-detection-app"}
  |= "source_ip=203.0.113.10"
  | json
  | line_format "{{.timestamp}} event={{.event_type}} user={{.username}}"

# Find the first and last failure timestamps
{app="threat-detection-app"} |= "AUTHENTICATION_FAILURE"
  | json
  | __error__=""
  | line_format "{{.timestamp}} user={{.username}} ip={{.source_ip}}"

# Check for successful logins in attack window (CRITICAL indicator)
{app="threat-detection-app", level="INFO"}
  |= "AUTHENTICATION_SUCCESS"
  | json
  | line_format "{{.timestamp}} user={{.username}} ip={{.source_ip}}"
```

### Prometheus — Metric-based analysis

```promql
# Failure rate over time by source IP
rate(failed_logins_total[5m])

# Top attacking IPs
topk(10, sum(increase(failed_logins_total[1h])) by (source_ip))

# Compare with baseline (past 24h)
avg_over_time(sum(rate(failed_logins_total[5m]))[24h:5m])
```

---

## Eradication

1. Ensure the attacking IP is blocked at the perimeter (WAF/firewall) — not just in-cluster
2. Rotate credentials for any targeted accounts
3. Review all accounts that received >3 failed attempts for signs of eventual success
4. Force re-authentication for active sessions of targeted accounts

```bash
# Force rotate any application secrets
kubectl create secret generic app-credentials \
  --from-literal=admin-password="$(openssl rand -base64 32)" \
  -n threat-detection \
  --dry-run=client -o yaml | kubectl apply -f -
```

---

## Recovery

```bash
# Verify attack has stopped
{app="threat-detection-app"} |= "AUTHENTICATION_FAILURE"
  | json | count_over_time([5m])

# Remove emergency isolation NetworkPolicy (if applied)
kubectl delete networkpolicy isolate-compromised-pod -n threat-detection

# Remove IP block (after extended quiet period — minimum 1 hour)
kubectl delete globalnetworkpolicy block-brute-force-source

# Verify Prometheus alert resolved
curl http://prometheus:9090/api/v1/alerts | jq '.data.alerts[] | select(.labels.alertname == "ExcessiveFailedLogins")'
```

---

## Lessons Learned Template

After every incident, complete within 24 hours:

| Question | Answer |
|----------|--------|
| When was the attack first detected? | |
| When did the first alert fire? | |
| Was detection within SLA (2 minutes)? | |
| Did any login succeed? | |
| How was the attack stopped? | |
| What would have prevented detection failure? | |
| What controls did NOT work? | |
| What alert tuning is needed? | |

**Detection SLA Review:**
- ExcessiveFailedLogins should fire within 2 minutes of first failure threshold being crossed
- BruteForceAttackCritical should fire within 1 minute (no `for:` delay)
- If either fired late, review Prometheus scrape interval and evaluation_interval

---

## Recommended Improvements (Post-Incident)

- [ ] Add WAF rate limiting rule (L7 — before traffic reaches K8s)
- [ ] Implement geo-blocking for high-risk origin countries
- [ ] Add CAPTCHA to login endpoint after N failures
- [ ] Configure fail2ban equivalent at ingress controller
- [ ] Add multi-factor authentication for privileged accounts
- [ ] Increase metric scrape frequency to 10s for auth endpoints

---

*Playbook owner: SOC Team | Last reviewed: 2024-01-01 | Next review: 2024-04-01*
