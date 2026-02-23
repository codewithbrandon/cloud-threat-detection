#!/usr/bin/env python3
"""
=============================================================================
Attack Simulation: Suspicious Container Runtime Events
=============================================================================
Simulates post-compromise attacker behavior inside a container to validate:

  1. Falco "shell_spawned_in_container" rule fires for /exec endpoint
  2. Falco "unexpected_outbound_connection" fires for /probe endpoint
  3. Falco "write_sensitive_file" fires for /file-write endpoint
  4. Prometheus "suspicious_activity_total" counter increments
  5. Loki "SuspiciousExecInLogs" alert triggers
  6. Alertmanager routes all events to #security-incidents

These simulate the attacker kill chain AFTER initial container access:
  T1059.004 — Shell execution
  T1071    — Network C2 beaconing
  T1222    — File system tampering
  T1057    — Process discovery

Usage:
    python3 attacks/suspicious_commands.py --target http://localhost:8080
    python3 attacks/suspicious_commands.py --target http://localhost:8080 --scenario all
=============================================================================
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%SZ'
)
logger = logging.getLogger("suspicious-commands-simulator")


def simulate_shell_execution(target: str, commands: list) -> list:
    """
    Simulates shell/command execution inside container.

    WHY THIS MATTERS: A Flask app running via Gunicorn should NEVER spawn
    a subprocess. Falco's shell_spawned_in_container rule fires on the
    exec() syscall, regardless of what the command does.
    """
    results = []
    logger.info(f"[EXEC] Simulating shell execution: {len(commands)} commands")

    for cmd in commands:
        logger.info(f"  Executing: '{cmd}'")
        try:
            response = requests.post(
                f"{target}/exec",
                json={"command": cmd},
                timeout=15
            )
            result = {
                "scenario": "shell_execution",
                "command": cmd,
                "status_code": response.status_code,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            if response.status_code == 200:
                data = response.json()
                result["output"] = data.get("output", "")
                result["detection_rule"] = data.get("detection_rule", "")
                logger.info(
                    f"  Result: {data.get('output', '')[:80]} | "
                    f"Rule: {data.get('detection_rule')}"
                )
            results.append(result)
            time.sleep(1)  # 1s between commands to generate distinct Falco events
        except Exception as e:
            logger.error(f"  Error: {e}")
            results.append({"command": cmd, "error": str(e)})

    return results


def simulate_network_probe(target: str, targets: list) -> list:
    """
    Simulates C2 beaconing / lateral movement network probes.

    WHY THIS MATTERS: Falco monitors connect() syscalls. Any connection
    to unexpected destinations triggers "unexpected_outbound_connection".
    NetworkPolicy blocks the actual packet, but Falco catches the syscall
    BEFORE the kernel drops it — providing earlier detection.
    """
    results = []
    logger.info(f"[NETWORK] Simulating {len(targets)} network probes")

    for probe_target in targets:
        logger.info(f"  Probing: {probe_target}")
        try:
            response = requests.post(
                f"{target}/probe",
                json={"target": probe_target},
                timeout=10
            )
            result = {
                "scenario": "network_probe",
                "target": probe_target,
                "status_code": response.status_code,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            if response.status_code == 200:
                data = response.json()
                result["blocked_by"] = data.get("blocked_by")
                result["detected_by"] = data.get("detected_by")
                logger.info(
                    f"  Probe logged | Blocked by: {data.get('blocked_by')} | "
                    f"Detected by: {data.get('detected_by')}"
                )
            results.append(result)
            time.sleep(0.5)
        except Exception as e:
            logger.error(f"  Error: {e}")
            results.append({"target": probe_target, "error": str(e)})

    return results


def simulate_file_tampering(target: str, count: int = 3) -> list:
    """
    Simulates file write to sensitive paths.

    WHY THIS MATTERS: Writing to /etc/passwd, /etc/crontab, or replacing
    binaries in /usr/bin are classic persistence mechanisms. Falco's
    write_sensitive_file rule fires on open() syscalls to these paths.
    readOnlyRootFilesystem blocks the actual write, but Falco still alerts.
    """
    results = []
    logger.info(f"[FILE] Simulating {count} file write attempts")

    for i in range(count):
        logger.info(f"  Write attempt {i+1}/{count}")
        try:
            response = requests.post(
                f"{target}/file-write",
                json={},
                timeout=10
            )
            result = {
                "scenario": "file_tampering",
                "attempt": i + 1,
                "status_code": response.status_code,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            if response.status_code == 200:
                data = response.json()
                result["simulated_target"] = data.get("simulated_target")
                result["detection_rule"] = data.get("detection_rule")
                logger.info(
                    f"  Target: {data.get('simulated_target')} | "
                    f"Rule: {data.get('detection_rule')}"
                )
            results.append(result)
            time.sleep(2)
        except Exception as e:
            logger.error(f"  Error: {e}")
            results.append({"attempt": i+1, "error": str(e)})

    return results


def run_full_kill_chain(target: str) -> dict:
    """
    Runs a complete attacker kill chain simulation in sequence.

    Kill chain phases:
    1. Reconnaissance — process/env enumeration (whoami, id, env)
    2. Discovery — network scanning (network probes)
    3. Persistence — file system modification (file write)
    4. C2 — outbound connection attempts (network probes to external IPs)

    WHY: Real attackers follow this sequence. Testing the full chain validates
    that detection systems are correlated (Falco → Loki → Alertmanager flow).
    """
    logger.info("=" * 60)
    logger.info("FULL KILL CHAIN SIMULATION")
    logger.info("T1059 → T1057 → T1222 → T1071")
    logger.info("=" * 60)

    results = {}

    # Phase 1: Reconnaissance
    logger.info("\n[PHASE 1] Reconnaissance — T1057 Process Discovery")
    results["reconnaissance"] = simulate_shell_execution(
        target, ["whoami", "id", "hostname", "ps", "env_list"]
    )
    time.sleep(2)

    # Phase 2: Discovery
    logger.info("\n[PHASE 2] Discovery — Network Enumeration")
    results["discovery"] = simulate_network_probe(
        target, [
            "192.168.1.1",    # Internal network gateway
            "10.0.0.1",       # Private range
            "203.0.113.100",  # External C2 simulation
        ]
    )
    time.sleep(2)

    # Phase 3: Persistence
    logger.info("\n[PHASE 3] Persistence — File System Tampering")
    results["persistence"] = simulate_file_tampering(target, count=2)
    time.sleep(2)

    # Phase 4: C2 Beaconing
    logger.info("\n[PHASE 4] C2 Beaconing — Outbound Connection Attempts")
    results["c2_beaconing"] = simulate_network_probe(
        target, [
            "203.0.113.200",  # Simulated C2 server
            "198.51.100.100", # Simulated C2 fallback
        ]
    )

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Suspicious Container Activity Simulation"
    )
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument(
        "--scenario",
        choices=["exec", "network", "file", "kill-chain"],
        default="kill-chain",
        help=(
            "exec: shell execution simulation (Falco: shell_spawned_in_container)\n"
            "network: network probe simulation (Falco: unexpected_outbound_connection)\n"
            "file: file write simulation (Falco: write_sensitive_file)\n"
            "kill-chain: full attacker kill chain sequence"
        )
    )
    parser.add_argument("--output", help="Write results to JSON file")
    args = parser.parse_args()

    print("=" * 70)
    print("  SUSPICIOUS CONTAINER ACTIVITY SIMULATION")
    print("  Cloud-Native Threat Detection Platform")
    print("=" * 70)
    print(f"  Target:    {args.target}")
    print(f"  Scenario:  {args.scenario}")
    print()
    print("  DETECTION EXPECTED:")
    print("  [x] Falco: shell_spawned_in_container (exec scenario)")
    print("  [x] Falco: unexpected_outbound_connection (network scenario)")
    print("  [x] Falco: write_sensitive_file (file scenario)")
    print("  [x] Prometheus: suspicious_activity_total counter")
    print("  [x] Loki: SuspiciousExecInLogs alert")
    print("  [x] Alertmanager: routes to #security-incidents")
    print("=" * 70)

    input("\nPress ENTER to start simulation (Ctrl+C to cancel)...")

    start = datetime.now(timezone.utc)
    results = {}

    try:
        if args.scenario == "exec":
            results["exec"] = simulate_shell_execution(
                args.target, ["whoami", "id", "hostname", "ps"]
            )
        elif args.scenario == "network":
            results["network"] = simulate_network_probe(
                args.target, ["192.168.1.1", "203.0.113.100"]
            )
        elif args.scenario == "file":
            results["file"] = simulate_file_tampering(args.target, count=3)
        elif args.scenario == "kill-chain":
            results = run_full_kill_chain(args.target)

    except KeyboardInterrupt:
        logger.info("Simulation interrupted")

    print("\n" + "=" * 70)
    print("  SIMULATION COMPLETE")
    print("=" * 70)
    total_events = sum(len(v) if isinstance(v, list) else 0 for v in results.values())
    print(f"  Total events generated: {total_events}")
    print()
    print("  VERIFY DETECTION:")
    print("  Falco logs: kubectl logs -n threat-detection -l app=falco -f")
    print("  Loki: {app=\"threat-detection-app\"} |= \"SUSPICIOUS_EXEC\"")
    print("  Prometheus: http://localhost:9090/graph?g0.expr=suspicious_activity_total")
    print("  Alertmanager: http://localhost:9093")
    print("=" * 70)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                "config": vars(args),
                "start": start.isoformat(),
                "results": results
            }, f, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(main())
