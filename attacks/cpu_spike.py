#!/usr/bin/env python3
"""
=============================================================================
Attack Simulation: CPU Spike / Resource Exhaustion
=============================================================================
Triggers sustained CPU usage via the /load endpoint to validate:

  1. Prometheus "HighCPUUsage" alert fires (>75% for >2 minutes)
  2. Prometheus "CriticalCPUSpike" alert fires (>95% for >1 minute)
  3. Kubernetes liveness probe fails under sustained load
  4. Alertmanager routes CPU alerts to #platform-oncall
  5. Loki "CPUSpikeInLogs" alert triggers from log events
  6. Pod becomes unready under load (readiness probe degradation)

Detection expected: Prometheus + Loki + Kubernetes events
MITRE ATT&CK: T1499 — Endpoint Denial of Service

Usage:
    python3 attacks/cpu_spike.py --target http://localhost:8080
    python3 attacks/cpu_spike.py --target http://localhost:8080 --intensity 1.0 --duration 120
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
    level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("cpu-spike-simulator")


def trigger_cpu_spike(
    target: str,
    intensity: float,
    duration: int,
    repeat: int = 1,
    interval: float = 5.0,
) -> list:
    """
    Triggers CPU spike via /load endpoint.

    Args:
        target: Base URL of target application
        intensity: CPU spike intensity 0.0-1.0 (maps to 70-99% CPU)
        duration: Duration in seconds for each spike
        repeat: Number of spike events to trigger
        interval: Seconds between spike events
    """
    results = []

    for i in range(repeat):
        logger.info(
            f"[SPIKE {i+1}/{repeat}] Triggering CPU spike: "
            f"intensity={intensity:.1%} duration={duration}s"
        )

        try:
            start = time.time()
            response = requests.post(
                f"{target}/load",
                json={"duration": duration, "intensity": intensity},
                timeout=30,
                headers={"Content-Type": "application/json"},
            )
            elapsed = time.time() - start

            result = {
                "spike": i + 1,
                "intensity": intensity,
                "duration_requested": duration,
                "status_code": response.status_code,
                "response_ms": round(elapsed * 1000, 1),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            if response.status_code == 200:
                logger.info(
                    f"[SPIKE {i+1}/{repeat}] Triggered successfully. "
                    f"Prometheus alert should fire in ~{120 if intensity < 0.9 else 60}s"
                )
            else:
                logger.error(f"[SPIKE {i+1}/{repeat}] Unexpected status: {response.status_code}")

            results.append(result)

            # Wait for spike to build up before triggering next
            if i < repeat - 1:
                logger.info(f"Waiting {interval}s before next spike...")
                time.sleep(interval)

        except requests.exceptions.RequestException as e:
            logger.error(f"[SPIKE {i+1}] Request failed: {e}")
            results.append(
                {
                    "spike": i + 1,
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

    return results


def monitor_alert_firing(target: str, prometheus_url: str, duration: int) -> None:
    """
    Polls Prometheus to check when alerts fire.
    WHY: Validates that the detection pipeline responds within expected SLA.
    Alert SLA: HighCPUUsage should fire within 2 minutes of sustained >75% CPU.
    """
    logger.info(f"Monitoring Prometheus for CPU alerts (poll every 15s for {duration}s)...")
    end_time = time.time() + duration
    alert_names = ["HighCPUUsage", "CriticalCPUSpike"]

    while time.time() < end_time:
        try:
            response = requests.get(f"{prometheus_url}/api/v1/alerts", timeout=10)
            if response.status_code == 200:
                data = response.json()
                firing = [
                    a for a in data.get("data", {}).get("alerts", [])
                    if a.get("labels", {}).get("alertname") in alert_names
                    and a.get("state") == "firing"
                ]
                if firing:
                    logger.info(f"ALERT FIRING: {[a['labels']['alertname'] for a in firing]}")
                    for alert in firing:
                        logger.info(f"  Alert: {alert['labels']['alertname']}")
                        logger.info(f"  State: {alert['state']}")
                        logger.info(f"  Value: {alert.get('annotations', {}).get('description', 'N/A')}")
                else:
                    remaining = int(end_time - time.time())
                    logger.info(f"No CPU alerts firing yet (checking again in 15s, {remaining}s remaining)")
        except Exception as e:
            logger.debug(f"Could not reach Prometheus: {e}")

        time.sleep(15)


def main():
    parser = argparse.ArgumentParser(
        description="CPU Spike Attack Simulation — Threat Detection Platform"
    )
    parser.add_argument("--target", default="http://localhost:8080", help="Target application URL")
    parser.add_argument(
        "--intensity",
        type=float,
        default=0.9,
        help="Spike intensity 0.0-1.0 (0.9 = 99% CPU, 0.7 = ~85% CPU)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=120,
        help="Duration in seconds for CPU spike",
    )
    parser.add_argument("--repeat", type=int, default=1, help="Number of spike events")
    parser.add_argument(
        "--prometheus",
        default="http://localhost:9090",
        help="Prometheus URL for alert monitoring",
    )
    parser.add_argument(
        "--monitor-alerts",
        action="store_true",
        help="Poll Prometheus to verify alert fires",
    )
    parser.add_argument("--output", help="Write results JSON to file")
    args = parser.parse_args()

    simulated_cpu = 70 + (args.intensity * 29)

    print("=" * 70)
    print("  CPU SPIKE ATTACK SIMULATION")
    print("  Cloud-Native Threat Detection Platform")
    print("=" * 70)
    print(f"  Target:           {args.target}")
    print(f"  Intensity:        {args.intensity:.1%} (~{simulated_cpu:.0f}% CPU)")
    print(f"  Duration:         {args.duration}s per spike")
    print(f"  Repeat:           {args.repeat}x")
    print()
    print("  DETECTION EXPECTED:")
    print("  [x] Prometheus: HighCPUUsage (>75% for 2min)")
    print("  [x] Prometheus: CriticalCPUSpike (>95% for 1min)" if args.intensity > 0.87 else "  [ ] CriticalCPUSpike (need intensity >0.87)")
    print("  [x] Loki: CPUSpikeInLogs (immediate from log event)")
    print("  [ ] Falco: NOT expected (no exec syscall)")
    print(f"  Alert expected in: ~{120 if simulated_cpu < 95 else 60}s")
    print("=" * 70)

    input("\nPress ENTER to start attack simulation (Ctrl+C to cancel)...")

    start = datetime.now(timezone.utc)
    results = trigger_cpu_spike(args.target, args.intensity, args.duration, args.repeat)

    if args.monitor_alerts:
        monitor_alert_firing(args.target, args.prometheus, args.duration + 180)

    print("\n" + "=" * 70)
    print("  CPU SPIKE SIMULATION COMPLETE")
    print("=" * 70)
    for r in results:
        status = r.get("status_code", "ERR")
        print(f"  Spike {r['spike']}: HTTP {status} | {r.get('response_ms', 0)}ms")
    print()
    print("  VERIFY DETECTION:")
    print(f"  Prometheus: {args.prometheus}/alerts")
    print('  Grafana Loki: {app="threat-detection-app"} |= "CPU_SPIKE"')
    print("=" * 70)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(
                {"config": vars(args), "start_time": start.isoformat(), "results": results},
                f,
                indent=2,
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
