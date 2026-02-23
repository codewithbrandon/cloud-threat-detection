# Incident Playbook: Container Compromise / Runtime Attack

**Playbook ID:** SEC-002
**Severity:** CRITICAL
**Owner:** Security Operations + Platform Engineering
**SLA:** Contain within 15 minutes of detection

---

## Overview

A container compromise indicates an attacker has achieved code execution within a running container. This is typically the result of exploiting an application vulnerability (RCE, command injection, SSTI) or a supply chain compromise.

**Why This Is Critical:**
- Containers share the host kernel — escape is possible
- Compromised containers can pivot to other services via ClusterIP
- Kubernetes API access (if SA token is mounted) enables cluster-wide impact
- Container logs and ephemeral storage may contain sensitive data

**MITRE ATT&CK Kill Chain:**
```
Initial Access → Execution → Persistence → Privilege Escalation →
Defense Evasion → Credential Access → Discovery → Lateral Movement →
Collection → Exfiltration / Impact
```

---

## Detection Signals

| Signal | Source | Trigger | Severity |
|--------|--------|---------|----------|
| `shell_spawned_in_container` | Falco | exec() syscall for shell binary | CRITICAL |
| `unexpected_outbound_connection` | Falco | connect() to non-whitelisted IP | HIGH |
| `write_sensitive_file` | Falco | open() with WRITE flag on /etc, /bin | CRITICAL |
| `dangerous_binary_in_container` | Falco | wget, curl, nc executed | HIGH |
| `crypto_miner_detected` | Falco | xmrig or stratum connection | CRITICAL |
| `privilege_escalation_attempt` | Falco | setuid/setgid syscall | CRITICAL |
| `SuspiciousExecInLogs` | Loki | SUSPICIOUS_EXEC_EVENT log line | CRITICAL |
| `suspicious_activity_total` | Prometheus | Any suspicious_exec activity | WARNING |

### Sample Falco Alert Output

```json
{
  "rule": "shell_spawned_in_container",
  "priority": "CRITICAL",
  "output": {
    "container": "threat-detection-app",
    "namespace": "threat-detection",
    "pod": "threat-detection-app-xyz123",
    "shell": "bash",
    "parent": "gunicorn",
    "cmdline": "bash -c id; whoami; cat /etc/passwd",
    "user": "appuser",
    "uid": 1001,
    "mitre_technique": "T1059.004"
  },
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

---

## Incident Timeline Template

```
[T+0:00]  Falco detects: shell_spawned_in_container
[T+0:01]  Falcosidekick routes alert → Alertmanager → #security-incidents
[T+0:02]  Loki alert: SuspiciousExecInLogs fires
[T+0:05]  SOC analyst acknowledges — incident declared
[T+0:08]  Pod isolated via NetworkPolicy (all ingress/egress blocked)
[T+0:10]  Forensic snapshot of pod filesystem collected
[T+0:12]  Pod terminated and replaced (clean rollout)
[T+0:15]  Root cause investigation begins
[T+0:30]  CISO, Engineering leads notified
[T+2:00]  Forensic analysis complete
[T+4:00]  Root cause identified
[T+24:00] RCA document and remediation plan delivered
[T+72:00] Remediation deployed and verified
```

---

## Immediate Containment (Execute within 5 minutes)

### Step 1: Identify the compromised pod

```bash
# Get pod name from Falco alert or Loki
POD_NAME="threat-detection-app-<pod-id>"
NAMESPACE="threat-detection"
NODE_NAME=$(kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.spec.nodeName}')

echo "Compromised pod: $POD_NAME"
echo "Running on node: $NODE_NAME"

# Check what processes are running
kubectl exec $POD_NAME -n $NAMESPACE -- ps aux 2>/dev/null || echo "Exec blocked"
```

### Step 2: Isolate the pod — network kill switch

```bash
# Apply emergency network isolation policy
# This cuts ALL ingress and egress for the specific pod
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-isolation-$(date +%s)
  namespace: ${NAMESPACE}
  labels:
    incident: "SEC-002"
    created-by: "soc-emergency-response"
spec:
  podSelector:
    matchLabels:
      app: threat-detection-app
      pod-name: ${POD_NAME}
  policyTypes:
    - Ingress
    - Egress
  # No ingress or egress rules = deny all
EOF

# Verify isolation applied
kubectl describe networkpolicy -n $NAMESPACE | grep -A5 emergency-isolation
```

### Step 3: Preserve forensic evidence BEFORE terminating pod

```bash
# --- FORENSIC COLLECTION ---
# Run all commands before pod termination — evidence is lost when pod dies

# 1. Capture running processes (even if exec is blocked, look at /proc)
kubectl exec $POD_NAME -n $NAMESPACE -- cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' > forensics-processes.txt

# 2. Capture active network connections
kubectl exec $POD_NAME -n $NAMESPACE -- netstat -antp 2>/dev/null > forensics-netstat.txt || true
kubectl exec $POD_NAME -n $NAMESPACE -- ss -antp 2>/dev/null >> forensics-netstat.txt || true

# 3. Capture environment variables (may contain injected C2 config)
kubectl exec $POD_NAME -n $NAMESPACE -- env 2>/dev/null > forensics-env.txt || true

# 4. Capture filesystem modifications (check /tmp for tools)
kubectl exec $POD_NAME -n $NAMESPACE -- find /tmp -type f -ls 2>/dev/null > forensics-tmp.txt || true

# 5. Export full pod specification (may show malicious injections)
kubectl get pod $POD_NAME -n $NAMESPACE -o yaml > forensics-pod-spec.yaml

# 6. Export logs (before pod termination destroys them)
kubectl logs $POD_NAME -n $NAMESPACE --all-containers > forensics-app-logs.txt
kubectl logs $POD_NAME -n $NAMESPACE --all-containers --previous > forensics-app-logs-prev.txt 2>/dev/null || true

# 7. Node-level forensics (if you have node access)
# ssh $NODE_NAME
# crictl inspect $(crictl ps | grep $POD_NAME | awk '{print $1}') > forensics-container-inspect.json
```

### Step 4: Cordon the node and terminate the pod

```bash
# Prevent new pods from being scheduled on the potentially compromised node
kubectl cordon $NODE_NAME

# Terminate the compromised pod
# Kubernetes will schedule a replacement on an uncordoned node
kubectl delete pod $POD_NAME -n $NAMESPACE --grace-period=0

# Verify replacement pod is running on a different node
kubectl get pods -n $NAMESPACE -o wide -w
```

---

## Investigation Procedures

### Falco Alert Analysis

```bash
# Query all Falco alerts for the incident window
kubectl logs -n threat-detection -l app=falco --since=1h | \
  jq 'select(.rule != null) | {rule, priority, container: .output_fields."container.name", pod: .output_fields."k8s.pod.name", cmdline: .output_fields."proc.cmdline"}'

# Find specific CRITICAL events
kubectl logs -n threat-detection -l app=falco --since=1h | \
  jq 'select(.priority == "Critical")'
```

### Loki Log Correlation

```logql
# All events from the compromised pod during incident window
{pod="threat-detection-app-xyz123"}
  | json
  | line_format "{{.timestamp}} [{{.level}}] {{.msg}}"

# Track the attack progression
{app="threat-detection-app"}
  |= "SUSPICIOUS"
  | json
  | line_format "{{.timestamp}} {{.event_type}} src={{.source_ip}}"

# Identify what commands were run
{app="threat-detection-app"}
  |= "SUSPICIOUS_EXEC_EVENT"
  | json
```

### Container Image Integrity Check

```bash
# Verify the running image hash matches the expected build
EXPECTED_DIGEST="sha256:<expected-hash-from-ci>"
RUNNING_DIGEST=$(kubectl get pod $POD_NAME -n $NAMESPACE \
  -o jsonpath='{.status.containerStatuses[0].imageID}')

if [ "$EXPECTED_DIGEST" != "$RUNNING_DIGEST" ]; then
  echo "IMAGE INTEGRITY VIOLATION: Running image does not match expected"
  echo "Expected: $EXPECTED_DIGEST"
  echo "Running:  $RUNNING_DIGEST"
  # Escalate immediately — possible supply chain compromise
fi
```

### Lateral Movement Assessment

```bash
# Check if compromised pod made any API calls before isolation
# (Kubernetes audit logs)
kubectl logs kube-apiserver-<node> -n kube-system | \
  grep $POD_NAME | grep -v "GET\|WATCH\|LIST"

# Check other pods in namespace for anomalous behavior
kubectl get pods -n threat-detection -o wide
kubectl top pods -n threat-detection

# Review all NetworkPolicy changes in incident window
kubectl get events -n threat-detection --sort-by='.lastTimestamp' | grep NetworkPolicy
```

---

## Eradication

```bash
# 1. Rebuild image from source (assume image is compromised)
# Trigger CI/CD pipeline to rebuild from clean source
git tag -a "emergency-rebuild-$(date +%Y%m%d)" -m "Emergency rebuild post-incident SEC-002"
git push origin --tags

# 2. Rotate ALL secrets in the namespace (assume credential theft)
# Service credentials
kubectl delete secret app-credentials -n threat-detection
kubectl create secret generic app-credentials \
  --from-literal=password="$(openssl rand -base64 32)" \
  -n threat-detection

# 3. Roll the deployment with the new image
kubectl rollout restart deployment/threat-detection-app -n threat-detection
kubectl rollout status deployment/threat-detection-app -n threat-detection

# 4. Uncordon node after investigation (or decommission if compromised)
kubectl uncordon $NODE_NAME  # Only after node investigation complete
```

---

## Root Cause Analysis Framework

Complete within 24 hours of containment:

### 5 Whys Example

```
Problem: Shell was spawned inside the application container

Why 1: The /exec endpoint called subprocess.run() with user input
Why 2: The endpoint was accessible without authentication
Why 3: Authentication was not required for internal simulation endpoints
Why 4: Internal endpoints were assumed to be unreachable externally
Why 5: NetworkPolicy did not restrict which pods could call /exec

Root Cause: Missing authentication + overly permissive NetworkPolicy
```

### Remediation Actions

| Finding | Remediation | Owner | Due |
|---------|-------------|-------|-----|
| /exec endpoint unauthenticated | Add API key auth or remove endpoint | App team | 48h |
| NetworkPolicy too permissive | Restrict /exec to admin pod only | Platform | 24h |
| No image signing | Implement Cosign image signing in CI/CD | DevSecOps | 1 week |
| Container escape possible | Enable seccomp RuntimeDefault on all pods | Platform | 1 week |

---

## Communication Templates

### Internal Escalation (T+5 min)

```
SECURITY INCIDENT — SEC-002 — CONTAINER COMPROMISE
Severity: CRITICAL
Time Detected: [timestamp]
Affected: threat-detection-app pod [pod-name] on node [node-name]
Status: Isolation applied, pod terminated, investigation in progress
Next Update: 30 minutes
Incident Commander: [name]
```

### CISO Briefing (T+30 min)

```
SECURITY INCIDENT BRIEF

Incident: Container compromise detected in threat-detection namespace
Detection: Falco runtime alert (shell spawned in application container)
Containment: Completed at [timestamp] — pod isolated and terminated
Impact: [Describe impact if any — data access, lateral movement, etc.]
Customer Impact: [None/Limited/Significant]
Regulatory: [Any GDPR/PCI/SOX notification triggers?]
ETA to RCA: 24 hours
```

---

## Lessons Learned Checklist

- [ ] Was the Falco rule tuned for minimum false positives?
- [ ] Did Falcosidekick → Alertmanager routing work correctly?
- [ ] Was the detection-to-containment time under 15 minutes?
- [ ] Were forensic artifacts collected before pod termination?
- [ ] Was the compromised node properly investigated?
- [ ] Were all secrets rotated?
- [ ] Was the image rebuild triggered from clean source?
- [ ] Was the vulnerability that enabled the compromise patched?
- [ ] Were other pods/namespaces assessed for same vulnerability?
- [ ] Was the incident logged in the security register?

---

*Playbook owner: SOC Team | Last reviewed: 2024-01-01 | Next review: 2024-04-01*
