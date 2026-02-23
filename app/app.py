"""
Cloud-Native Threat Detection Platform — Flask Application
==========================================================
Generates synthetic traffic, exposes Prometheus metrics, and simulates
real-world attack patterns for detection by Falco, Prometheus alerting,
and Loki log analytics.

WHY THIS EXISTS: Most container environments have zero runtime visibility.
This app serves as both the target workload AND the traffic/attack simulator,
enabling end-to-end detection testing without external infrastructure.
"""

import logging
import os
import random
import subprocess
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# ---------------------------------------------------------------------------
# Logging Configuration
# Structured JSON-style logging feeds Promtail → Loki for log-based alerting.
# Authentication failures are explicitly tagged for SIEM-style pattern matching.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s [%(funcName)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("threat-detection-app")

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Prometheus Metrics
# WHY: Pull-based metrics via /metrics let Prometheus scrape without needing
# push credentials. Each metric targets a specific alert rule.
# ---------------------------------------------------------------------------

# HTTP traffic counters — feeds "high_request_rate" and "5xx_error_rate" alerts
http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests received",
    ["method", "endpoint", "status_code"],
)

# Latency histogram — p95/p99 buckets for SLO tracking
http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# Failed login counter — primary trigger for brute force detection alert
failed_logins_total = Counter(
    "failed_logins_total",
    "Total failed login attempts — used to trigger brute force alerts",
    ["source_ip", "username"],
)

# Simulated CPU gauge — triggers "cpu_spike_detected" Prometheus alert
cpu_usage_percent = Gauge(
    "app_cpu_usage_percent",
    "Simulated CPU usage percentage reported by the application",
)

# Memory gauge — triggers "memory_pressure_detected" alert
memory_usage_bytes = Gauge(
    "app_memory_usage_bytes",
    "Simulated memory usage in bytes reported by the application",
)

# Pod restart counter — complements kube_pod_container_status_restarts_total
app_errors_total = Counter(
    "app_errors_total",
    "Total application errors by category",
    ["category"],
)

# Active connections gauge — baseline for anomaly detection
active_connections = Gauge(
    "app_active_connections",
    "Number of currently active client connections",
)

# Suspicious activity counter — feeds security-specific alert channel
suspicious_activity_total = Counter(
    "suspicious_activity_total",
    "Total suspicious events detected by the application",
    ["activity_type"],
)


# ---------------------------------------------------------------------------
# Background Metric Simulation
# WHY: Real workloads show baseline CPU/memory variation. Simulating realistic
# baselines prevents alert fatigue from false positives on flat metrics.
# ---------------------------------------------------------------------------


def simulate_baseline_metrics():
    """
    Continuously update CPU and memory gauges with realistic baseline noise.
    Values stay low under normal conditions, enabling spike detection by delta.
    """
    while True:
        # Normal baseline: 5-25% CPU, 64-256MB memory
        base_cpu = random.uniform(5.0, 25.0)
        base_mem = random.uniform(64 * 1024 * 1024, 256 * 1024 * 1024)
        cpu_usage_percent.set(base_cpu)
        memory_usage_bytes.set(base_mem)
        active_connections.set(random.randint(1, 20))
        time.sleep(15)


baseline_thread = threading.Thread(target=simulate_baseline_metrics, daemon=True)
baseline_thread.start()


# ---------------------------------------------------------------------------
# Middleware: Request instrumentation
# ---------------------------------------------------------------------------


@app.before_request
def before_request():
    request.start_time = time.time()
    active_connections.inc()


@app.after_request
def after_request(response):
    duration = time.time() - request.start_time
    endpoint = request.endpoint or "unknown"
    http_requests_total.labels(
        method=request.method,
        endpoint=endpoint,
        status_code=str(response.status_code),
    ).inc()
    http_request_duration_seconds.labels(method=request.method, endpoint=endpoint).observe(duration)
    active_connections.dec()
    return response


# ---------------------------------------------------------------------------
# Health & Readiness
# WHY: Kubernetes liveness probe hits /health. If the app is deadlocked or
# OOM-killed, the probe fails and triggers pod restart — logged by Loki,
# alerted by Alertmanager "pod_crash_loop" rule.
# ---------------------------------------------------------------------------


@app.route("/health", methods=["GET"])
def health():
    return (
        jsonify(
            {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": os.environ.get("APP_VERSION", "1.0.0"),
                "service": "threat-detection-app",
            }
        ),
        200,
    )


@app.route("/ready", methods=["GET"])
def ready():
    """Readiness probe — separates startup delay from runtime failure."""
    return jsonify({"status": "ready"}), 200


# ---------------------------------------------------------------------------
# Login Endpoint — Brute Force Detection Target
# WHY: The /login endpoint is the most commonly attacked web surface.
# We simulate realistic authentication flows with configurable failure rates.
# Falco detects if a real shell is spawned; Prometheus detects rate spikes.
# ---------------------------------------------------------------------------

# Simulated user database — intentionally weak for demo purposes
VALID_CREDENTIALS = {
    "admin": "SecureP@ss2024!",
    "monitor": "M0n1tor$ecure",
    "operator": "Ops#2024Secure",
}

# Track per-IP failure counts for in-app rate limiting simulation
_login_failure_tracker = {}
_tracker_lock = threading.Lock()


@app.route("/login", methods=["POST"])
def login():
    """
    Simulates authentication with realistic failure logging.

    Detection hooks:
    - failed_logins_total metric → Prometheus alert "ExcessiveFailedLogins"
    - Log line "AUTHENTICATION_FAILURE" → Loki alert rule
    - Rapid sequence from same IP → anomaly baseline deviation
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    source_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    if not username or not password:
        app_errors_total.labels(category="bad_request").inc()
        return jsonify({"error": "username and password required"}), 400

    # Track failures per IP for in-memory rate analysis
    with _tracker_lock:
        failures = _login_failure_tracker.get(source_ip, 0)

    # Simulate authentication check
    valid_password = VALID_CREDENTIALS.get(username)
    if valid_password and password == valid_password:
        logger.info(f"AUTHENTICATION_SUCCESS user={username} source_ip={source_ip}")
        with _tracker_lock:
            _login_failure_tracker[source_ip] = 0  # reset on success
        return (
            jsonify(
                {
                    "status": "authenticated",
                    "username": username,
                    "token": f"sim-token-{int(time.time())}",
                }
            ),
            200,
        )
    else:
        # Increment Prometheus counter — feeds Alertmanager rule
        failed_logins_total.labels(source_ip=source_ip, username=username).inc()

        with _tracker_lock:
            _login_failure_tracker[source_ip] = failures + 1
            current_failures = _login_failure_tracker[source_ip]

        # Structured log — Loki pipeline stage extracts severity
        logger.warning(
            f"AUTHENTICATION_FAILURE user={username} source_ip={source_ip} "
            f"consecutive_failures={current_failures}"
        )

        # Flag as suspicious after threshold — triggers suspicious_activity alert
        if current_failures >= 5:
            suspicious_activity_total.labels(activity_type="brute_force_attempt").inc()
            logger.error(
                f"BRUTE_FORCE_DETECTED user={username} source_ip={source_ip} "
                f"failures={current_failures} action=rate_limit_triggered"
            )
            return jsonify({"error": "account temporarily locked"}), 429

        return jsonify({"error": "invalid credentials"}), 401


# ---------------------------------------------------------------------------
# CPU Load Endpoint — Spike Detection Target
# WHY: Unexpected CPU spikes in containers often indicate crypto mining,
# fork bombs, or runaway processes. This endpoint simulates the pattern
# so Prometheus "HighCPUUsage" alert logic can be validated.
# ---------------------------------------------------------------------------


@app.route("/load", methods=["POST"])
def load():
    """
    Simulates CPU spike by running compute-intensive work.

    Detection hooks:
    - app_cpu_usage_percent gauge → Prometheus "HighCPUUsage" alert
    - Falco rule detects if this spawns unexpected child processes
    - Log tagged "CPU_SPIKE_EVENT" for Loki correlation
    """
    data = request.get_json(silent=True) or {}
    duration_seconds = min(int(data.get("duration", 10)), 60)  # max 60s cap
    intensity = min(float(data.get("intensity", 0.8)), 1.0)

    logger.warning(
        f"CPU_SPIKE_EVENT duration={duration_seconds}s intensity={intensity} "
        f"source_ip={request.remote_addr} event=cpu_load_triggered"
    )

    suspicious_activity_total.labels(activity_type="cpu_spike").inc()

    def cpu_spike_worker():
        end_time = time.time() + duration_seconds
        spike_cpu = 70.0 + (intensity * 29.0)  # 70-99% range
        cpu_usage_percent.set(spike_cpu)
        logger.warning(f"CPU_SPIKE_ACTIVE cpu_percent={spike_cpu:.1f}")
        # Simulate actual CPU work
        while time.time() < end_time:
            _ = [x**2 for x in range(10000)]
        # Restore baseline
        cpu_usage_percent.set(random.uniform(5.0, 25.0))
        logger.info("CPU_SPIKE_RESOLVED cpu_percent=baseline")

    spike_thread = threading.Thread(target=cpu_spike_worker, daemon=True)
    spike_thread.start()

    return (
        jsonify(
            {
                "status": "cpu_spike_triggered",
                "duration_seconds": duration_seconds,
                "intensity": intensity,
                "warning": "This action is logged and alerted",
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# Memory Pressure Endpoint — OOM Detection Target
# WHY: Memory exhaustion is a common DoS vector in multi-tenant Kubernetes.
# Resource limits prevent node-level impact; this simulates app-level pressure
# so Alertmanager "HighMemoryUsage" rule triggers before OOM kill occurs.
# ---------------------------------------------------------------------------

_memory_hog = []  # intentionally module-level to simulate resident memory
_memory_lock = threading.Lock()


@app.route("/memory", methods=["POST"])
def memory_pressure():
    """
    Simulates memory exhaustion by allocating a large byte array.

    Detection hooks:
    - app_memory_usage_bytes gauge → Prometheus "HighMemoryUsage" alert
    - Kubernetes OOM kill → kube_pod_container_status_restarts_total spike
    - Log "MEMORY_PRESSURE_EVENT" → Loki pipeline extraction
    """
    data = request.get_json(silent=True) or {}
    size_mb = min(int(data.get("size_mb", 100)), 512)  # cap at 512MB

    logger.warning(
        f"MEMORY_PRESSURE_EVENT size_mb={size_mb} "
        f"source_ip={request.remote_addr} event=memory_exhaustion_triggered"
    )

    suspicious_activity_total.labels(activity_type="memory_exhaustion").inc()
    app_errors_total.labels(category="resource_abuse").inc()

    with _memory_lock:
        # Allocate memory block to simulate pressure
        chunk = bytearray(size_mb * 1024 * 1024)
        _memory_hog.append(chunk)
        total_allocated = sum(len(b) for b in _memory_hog)
        memory_usage_bytes.set(total_allocated)

    logger.warning(
        f"MEMORY_ALLOCATED size_mb={size_mb} "
        f"total_allocated_bytes={total_allocated}"
    )

    return (
        jsonify(
            {
                "status": "memory_pressure_triggered",
                "allocated_mb": size_mb,
                "total_allocated_bytes": total_allocated,
                "warning": "Pod may be OOM-killed by Kubernetes",
            }
        ),
        200,
    )


@app.route("/memory/release", methods=["POST"])
def memory_release():
    """Release allocated memory — use after memory pressure test."""
    with _memory_lock:
        _memory_hog.clear()
        memory_usage_bytes.set(random.uniform(64 * 1024 * 1024, 256 * 1024 * 1024))
    logger.info("MEMORY_RELEASED event=memory_freed")
    return jsonify({"status": "memory_released"}), 200


# ---------------------------------------------------------------------------
# Suspicious Command Endpoint — Falco Runtime Detection Target
# WHY: Falco monitors syscalls. Spawning a shell or running system commands
# inside a container is a primary indicator of container escape attempts.
# This endpoint triggers Falco's "shell_in_container" detection rule.
# ---------------------------------------------------------------------------


@app.route("/exec", methods=["POST"])
def suspicious_exec():
    """
    Simulates suspicious command execution inside the container.

    Detection hooks:
    - Falco rule "shell_spawned_in_container" → Falco alert
    - Log "SUSPICIOUS_EXEC_EVENT" → Loki high-severity extraction
    - suspicious_activity_total metric → Prometheus security alert

    IMPORTANT: Only safe, read-only commands are actually executed.
    The syscall pattern is what Falco detects, not the command output.
    """
    data = request.get_json(silent=True) or {}
    # Whitelist of safe demonstration commands only
    safe_commands = {
        "whoami": ["whoami"],
        "id": ["id"],
        "hostname": ["hostname"],
        "ps": ["ps", "aux"],
        "netstat": ["netstat", "-an"],
        "env_list": ["env"],
    }

    requested = data.get("command", "whoami")
    command = safe_commands.get(requested, safe_commands["whoami"])

    logger.error(
        f"SUSPICIOUS_EXEC_EVENT command={requested} "
        f"source_ip={request.remote_addr} "
        f"event=shell_execution_in_container "
        f"severity=HIGH "
        f"falco_rule=shell_spawned_in_container"
    )

    suspicious_activity_total.labels(activity_type="suspicious_exec").inc()
    app_errors_total.labels(category="security_event").inc()

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout.strip()
    except Exception as e:
        output = f"execution_error: {str(e)}"
        logger.error(f"EXEC_ERROR command={requested} error={str(e)}")

    return (
        jsonify(
            {
                "status": "command_executed",
                "command": requested,
                "output": output,
                "warning": "This event triggered Falco runtime alert",
                "severity": "HIGH",
                "detection_rule": "shell_spawned_in_container",
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# Network Probe Endpoint — Unexpected Egress Detection Target
# WHY: Containers should only communicate with defined services.
# Unexpected outbound connections indicate C2 beaconing or data exfiltration.
# ---------------------------------------------------------------------------


@app.route("/probe", methods=["POST"])
def network_probe():
    """
    Simulates unexpected network connection attempt.

    Detection hooks:
    - Falco rule "unexpected_outbound_connection" (if network policy bypassed)
    - NetworkPolicy blocks actual egress (enforcement layer)
    - Log "SUSPICIOUS_NETWORK_EVENT" → Loki security pipeline
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target", "192.168.1.1")

    logger.error(
        f"SUSPICIOUS_NETWORK_EVENT target={target} "
        f"source_ip={request.remote_addr} "
        f"event=unexpected_egress_attempt "
        f"severity=CRITICAL "
        f"falco_rule=unexpected_outbound_connection"
    )

    suspicious_activity_total.labels(activity_type="network_probe").inc()

    return (
        jsonify(
            {
                "status": "probe_logged",
                "target": target,
                "blocked_by": "NetworkPolicy",
                "detected_by": ["Falco", "Loki", "Prometheus"],
                "severity": "CRITICAL",
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# File Write Simulation — Falco File Integrity Detection Target
# WHY: Writing to sensitive paths (/etc, /bin, /usr) inside a running
# container indicates tampering or persistence attempts.
# ---------------------------------------------------------------------------


@app.route("/file-write", methods=["POST"])
def suspicious_file_write():
    """
    Simulates suspicious file write to sensitive path.

    Detection hooks:
    - Falco rule "write_sensitive_file" triggers on /etc writes
    - Log "SUSPICIOUS_FILE_WRITE" → Loki alert
    - Only writes to /tmp in practice (safe demo)
    """
    # No body parameters used — endpoint is trigger-only
    # Always safe — only /tmp writes allowed
    safe_path = "/tmp/simulated_threat_artifact.txt"

    logger.error(
        f"SUSPICIOUS_FILE_WRITE path={safe_path} "
        f"simulated_target=/etc/passwd "
        f"source_ip={request.remote_addr} "
        f"event=sensitive_file_write_attempt "
        f"severity=HIGH "
        f"falco_rule=write_sensitive_file"
    )

    suspicious_activity_total.labels(activity_type="file_write").inc()

    try:
        with open(safe_path, "a") as f:
            f.write(f"[{datetime.now(timezone.utc).isoformat()}] Simulated threat artifact\n")
        write_status = "success"
    except Exception as e:
        write_status = f"error: {str(e)}"

    return (
        jsonify(
            {
                "status": "file_write_simulated",
                "actual_path": safe_path,
                "simulated_target": "/etc/passwd",
                "write_status": write_status,
                "severity": "HIGH",
                "detection_rule": "write_sensitive_file",
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# Prometheus Metrics Endpoint
# WHY: Standard /metrics path for Prometheus scraping. ServiceMonitor CR
# references this path; no auth required since it's cluster-internal only.
# ---------------------------------------------------------------------------


@app.route("/metrics", methods=["GET"])
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


# ---------------------------------------------------------------------------
# Status Overview
# ---------------------------------------------------------------------------


@app.route("/", methods=["GET"])
def index():
    return (
        jsonify(
            {
                "service": "Cloud-Native Threat Detection Platform",
                "version": os.environ.get("APP_VERSION", "1.0.0"),
                "endpoints": {
                    "GET  /health": "Kubernetes liveness probe",
                    "GET  /ready": "Kubernetes readiness probe",
                    "GET  /metrics": "Prometheus metrics scrape endpoint",
                    "POST /login": "Authentication endpoint (brute force target)",
                    "POST /load": "CPU spike simulation",
                    "POST /memory": "Memory pressure simulation",
                    "POST /memory/release": "Release allocated memory",
                    "POST /exec": "Suspicious command execution (Falco target)",
                    "POST /probe": "Network probe simulation",
                    "POST /file-write": "Suspicious file write simulation",
                },
                "detection_layers": [
                    "Prometheus metrics + Alertmanager",
                    "Falco runtime syscall monitoring",
                    "Loki log aggregation + alerts",
                    "Kubernetes NetworkPolicy enforcement",
                ],
            }
        ),
        200,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info(f"Starting threat-detection-app on port={port} debug={debug}")
    app.run(host="0.0.0.0", port=port, debug=debug)
