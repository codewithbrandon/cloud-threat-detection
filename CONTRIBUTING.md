# Contributing

Thanks for your interest. This is primarily a portfolio and educational
repository, but contributions that improve correctness, realism, or
documentation are welcome.

---

## Development Setup

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.10+ | [python.org](https://www.python.org) |
| Docker | 24+ | [docker.com](https://www.docker.com) |
| kubectl | 1.28+ | [kubernetes.io](https://kubernetes.io/docs/tasks/tools/) |
| helm | 3.x | [helm.sh](https://helm.sh/docs/intro/install/) |

### Local environment

```bash
# Clone
git clone https://github.com/codewithbrandon/cloud-threat-detection.git
cd cloud-threat-detection

# Python dependencies for linting
pip install ruff==0.4.10 black==24.4.2 yamllint==1.35.1

# Run all local quality checks (mirrors CI)
make lint
```

---

## Quality Gates

All pull requests must pass CI before merging. Run checks locally first:

```bash
# YAML lint (all manifests)
make lint-yaml

# Python format check
make lint-python

# Kubernetes schema validation
make validate-k8s

# Full lint suite
make lint
```

See the [CI workflow](.github/workflows/ci.yml) for the exact commands CI runs.

---

## What to Contribute

**Welcome:**
- Bug fixes in Python application logic or manifest configuration
- Additional Falco rules (with MITRE ATT&CK reference and clear WHY comment)
- Additional Prometheus alert rules (with documented thresholds and rationale)
- Documentation improvements — clearer explanations, corrected commands
- Grafana dashboard JSON files under `monitoring/grafana/`

**Please avoid:**
- Changing the project's core architecture (three-layer detection model)
- Removing the attack simulation scripts — they are fundamental to the demo
- Adding new external service dependencies without documented justification
- Weakening security controls (removing `readOnlyRootFilesystem`, adding `privileged: true`, etc.)

---

## Pull Request Guidelines

1. **Branch from `main`**: `git checkout -b fix/your-description`
2. **Run `make lint`** before pushing — CI will fail if you don't
3. **Write a clear PR description** explaining what changed and why
4. **Keep PRs focused** — one logical change per PR
5. **Do not commit secrets** — the Gitleaks CI job will catch them, but don't test it

### Commit message format

```
type: short description (max 72 chars)

Optional longer explanation of WHY, not WHAT.
```

Types: `feat`, `fix`, `docs`, `ci`, `refactor`, `chore`

Example:
```
feat: add Falco rule for ptrace syscall (T1055 process injection)

Detects ptrace() calls from inside application containers which are
not expected in normal Gunicorn operation. Maps to MITRE ATT&CK
T1055 — Process Injection.
```

---

## Code Style

| Language | Tool | Config |
|----------|------|--------|
| Python | `black` + `ruff` | `pyproject.toml` |
| YAML | `yamllint` | `.yamllint.yml` |
| All files | EditorConfig | `.editorconfig` |

---

## Adding a New Alert Rule

When adding a Prometheus or LogQL alert rule, include all of the following:

```yaml
- alert: MyNewAlert
  expr: |
    <promql expression>
  for: <duration>
  labels:
    severity: warning|critical
    team: security|platform
    category: <category>
  annotations:
    summary: "One-line human summary"
    description: |
      Full description including:
      - Current value: {{ $value }}
      - Why this threshold matters
      - What to do next
    runbook_url: "https://github.com/codewithbrandon/cloud-threat-detection/blob/main/docs/<playbook>.md"
```

---

## Reporting Issues

Use [GitHub Issues](https://github.com/codewithbrandon/cloud-threat-detection/issues)
for bugs, documentation errors, or improvement ideas.

For **security vulnerabilities**, use the private reporting process described
in [SECURITY.md](SECURITY.md) instead of opening a public issue.
