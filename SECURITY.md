# Security Policy

## Purpose

This repository is an **educational and portfolio demonstration** of cloud-native
threat detection patterns. It is not a commercial product or production system.

---

## Scope

This policy covers the code and configuration files in this repository.

**In scope for responsible disclosure:**
- Vulnerabilities in the Python application code (`app/`, `attacks/`)
- Security misconfigurations in Kubernetes manifests (`k8s/`, `monitoring/`)
- Dockerfile security issues (`docker/`)
- Dependency vulnerabilities in `requirements.txt` or `pyproject.toml`

**Out of scope:**
- The demo attack simulation scripts — these are **intentional** and exist to
  generate detection signals. They are not vulnerabilities.
- Issues in third-party tools (Prometheus, Loki, Falco, Alertmanager) — report
  those to the respective upstream projects.
- Theoretical attacks with no practical impact on the demo environment.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you find a genuine vulnerability in this repository's code or configuration:

1. Open a [GitHub Security Advisory](https://github.com/codewithbrandon/cloud-threat-detection/security/advisories/new)
   using the private reporting flow.
2. Include:
   - A clear description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested remediation (if known)

You will receive a response within **7 days**.

---

## Attack Simulation Scripts

The `attacks/` directory contains scripts that simulate brute force, CPU
exhaustion, memory pressure, and container runtime attacks. These are
**designed to be used against the local demo environment only**.

- Do **not** run these scripts against systems you do not own or have explicit
  written authorization to test.
- All simulated "attack" traffic targets `localhost` or an in-cluster service
  by design.
- The scripts follow MITRE ATT&CK techniques at a conceptual level for
  educational purposes — they do not implement destructive payloads.

---

## Dependency Updates

Pinned dependency versions in `requirements.txt` are intentional for
reproducibility. Check for CVEs using:

```bash
# Scan with Trivy
trivy fs --scanners vuln .

# Or with pip-audit
pip install pip-audit
pip-audit -r app/requirements.txt
```

CI runs a Trivy container scan on every push. Results are visible in the
[GitHub Security tab](https://github.com/codewithbrandon/cloud-threat-detection/security).

---

## Supported Versions

This is a demo repository. Only the `main` branch is maintained.
No versioned release support policy applies.
