#!/usr/bin/env python3
"""
=============================================================================
Attack Simulation: Memory Exhaustion
=============================================================================
Simulates memory exhaustion attack to validate:

  1. Prometheus "HighMemoryUsage" alert fires (>384Mi for 2min)
  2. Prometheus "MemoryExhaustionCritical" alert fires (>460Mi)
  3. Kubernetes OOM kill → pod restart → PodCrashLoopDetected alert
  4. Loki "MemoryExhaustionInLogs" alert triggers
  5. kube_pod_container_status_restarts_total increments

MITRE ATT&CK: T1499.004 — Application or System Exploitation

Usage:
    python3 attacks/memory_exhaustion.py --target http://localhost:8080
    python3 attacks/memory_exhaustion.py --target http://localhost:8080 --size 450 --steps 3
=============================================================================
"""

import argparse
import sys
import time
import logging
import json
from datetime import datetime, timezone

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%SZ'
)
logger = logging.getLogger("memory-exhaustion-simulator")


def trigger_memory_allocation(
    target: str,
    size_mb: int
) -> dict:
    """Trigger memory allocation via /memory endpoint."""
    try:
        response = requests.post(
            f"{target}/memory",
            json={"size_mb": size_mb},
            timeout=15
        )
        result = {
            "size_mb": size_mb,
            "status_code": response.status_code,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        if response.status_code == 200:
            data = response.json()
            result["total_allocated_bytes"] = data.get("total_allocated_bytes", 0)
            result["total_allocated_mb"] = round(result["total_allocated_bytes"] / (1024**2), 1)
        return result
    except requests.exceptions.RequestException as e:
        return {"size_mb": size_mb, "error": str(e)}


def release_memory(target: str) -> dict:
    """Release all allocated memory via /memory/release endpoint."""
    try:
        response = requests.post(f"{target}/memory/release", timeout=10)
        return {"status_code": response.status_code, "released": True}
    except Exception as e:
        return {"error": str(e), "released": False}


def run_escalating_exhaustion(
    target: str,
    steps: int,
    max_mb: int,
    hold_seconds: int
) -> list:
    """
    Gradually escalates memory allocation in steps.
    WHY: Gradual escalation mirrors real memory leak patterns and tests
    whether Prometheus alert fires before the OOM kill threshold is reached.
    """
    results = []
    step_size = max_mb // steps

    logger.info(
        f"[ESCALATING] Starting gradual memory exhaustion: "
        f"steps={steps} max={max_mb}MB step_size={step_size}MB"
    )

    for step in range(1, steps + 1):
        allocation = step_size
        total_expected = step * step_size

        logger.info(
            f"[STEP {step}/{steps}] Allocating {allocation}MB "
            f"(total expected: ~{total_expected}MB / 512MB limit)"
        )

        result = trigger_memory_allocation(target, allocation)
        result["step"] = step
        results.append(result)

        total = result.get("total_allocated_mb", 0)
        pct = (total / 512) * 100 if total else 0
        logger.info(
            f"[STEP {step}/{steps}] Total allocated: {total}MB "
            f"({pct:.0f}% of 512MB limit)"
        )

        # Alert thresholds
        if total >= 384:
            logger.warning(
                "THRESHOLD CROSSED: HighMemoryUsage (75% of limit). "
                "Prometheus alert should fire within 2 minutes."
            )
        if total >= 460:
            logger.warning(
                "THRESHOLD CROSSED: MemoryExhaustionCritical (90% of limit). "
                "OOM kill imminent. Prometheus critical alert firing."
            )

        if step < steps:
            logger.info(f"Holding for {hold_seconds}s before next allocation...")
            time.sleep(hold_seconds)

    return results


def run_sudden_exhaustion(target: str, size_mb: int) -> list:
    """
    Single large allocation to immediately trigger critical threshold.
    Simulates sudden memory spike (malicious allocation, OOM exploit).
    """
    logger.info(f"[SUDDEN] Single allocation of {size_mb}MB to trigger immediate alert")
    result = trigger_memory_allocation(target, size_mb)
    result["mode"] = "sudden"
    return [result]


def main():
    parser = argparse.ArgumentParser(
        description="Memory Exhaustion Simulation — Threat Detection Platform"
    )
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument(
        "--mode",
        choices=["escalating", "sudden"],
        default="escalating",
        help="escalating: gradual allocation (tests early warning alert)\n"
             "sudden: single large allocation (tests critical alert)"
    )
    parser.add_argument("--size", type=int, default=480, help="Max MB to allocate")
    parser.add_argument("--steps", type=int, default=4, help="Number of allocation steps")
    parser.add_argument("--hold", type=int, default=30, help="Seconds between steps")
    parser.add_argument("--no-release", action="store_true", help="Don't release memory after test")
    parser.add_argument("--output", help="Write results to JSON file")
    args = parser.parse_args()

    print("=" * 70)
    print("  MEMORY EXHAUSTION SIMULATION")
    print("  Cloud-Native Threat Detection Platform")
    print("=" * 70)
    print(f"  Target:     {args.target}")
    print(f"  Mode:       {args.mode}")
    print(f"  Max size:   {args.size}MB (limit: 512MB)")
    print(f"  Thresholds: HighMemory=384MB | Critical=460MB | OOMKill=512MB")
    print()
    print("  DETECTION EXPECTED:")
    print("  [x] Prometheus: HighMemoryUsage (>384Mi for 2min)")
    print("  [x] Prometheus: MemoryExhaustionCritical (>460Mi immediate)")
    print("  [x] Loki: MemoryExhaustionInLogs")
    print("  [x] Kubernetes: OOM kill → pod restart → PodCrashLoop alert")
    print("=" * 70)

    input("\nPress ENTER to start attack simulation (Ctrl+C to cancel)...")

    start = datetime.now(timezone.utc)
    results = []

    try:
        if args.mode == "escalating":
            results = run_escalating_exhaustion(
                args.target, args.steps, args.size, args.hold
            )
        else:
            results = run_sudden_exhaustion(args.target, args.size)

    except KeyboardInterrupt:
        logger.info("Simulation interrupted")
    finally:
        if not args.no_release:
            logger.info("Releasing allocated memory...")
            release_result = release_memory(args.target)
            logger.info(f"Memory release: {release_result}")

    print("\n" + "=" * 70)
    print("  MEMORY EXHAUSTION SIMULATION COMPLETE")
    print("=" * 70)
    for r in results:
        step = r.get("step", "N/A")
        mb = r.get("size_mb", "?")
        total = r.get("total_allocated_mb", "?")
        status = r.get("status_code", "ERR")
        print(f"  Step {step}: +{mb}MB | Total: {total}MB | HTTP {status}")

    print()
    print("  VERIFY DETECTION:")
    print("  Prometheus: http://localhost:9090/alerts")
    print("  Loki: {app=\"threat-detection-app\"} |= \"MEMORY_PRESSURE\"")
    print("  Pod status: kubectl get pods -n threat-detection -w")
    print("=" * 70)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({"config": vars(args), "start": start.isoformat(), "results": results}, f, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(main())
