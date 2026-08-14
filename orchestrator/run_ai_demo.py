"""AI test mode: mocked alerts, real inference, real SOAR delivery.

The difference from ``seed_demo_alert.py`` / ``simulate_alerts.py`` is what is
faked. Those install a ``ScriptedProvider`` and hand the broker a canned answer —
nothing reasons about anything. This script fakes only the *source* (synthetic Suricata
alerts instead of Splunk) and then posts them to a **running broker over HTTP**,
so the model on the GPU actually reads each alert, writes the enrichment, and
returns its own Tier-2 verdict.

With ``TIER2_AUTOPILOT=1`` on the broker, any CONTAIN/ESCALATE verdict at or
above the confidence threshold is approved and executed automatically, and each
action is delivered to the configured SOAR sink (default: a JSONL file).

    # terminal 1 — broker with autopilot on
    TIER2_AUTOPILOT=1 TIER2_AUTOPILOT_MIN_CONFIDENCE=90 \
      python -m uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500

    # terminal 2
    python run_ai_demo.py --count 8 --interval 5

Inference is slow on a notebook: budget 10-40s per alert and keep --count low
for a showroom run.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import random
import sys
import time
from datetime import datetime

import httpx

from seed_demo_alert import SCENARIO_TEMPLATES, build_scenario, reset_demo_data

DEFAULT_BROKER = 'http://127.0.0.1:8500'


async def _preflight(client: httpx.AsyncClient, broker_url: str) -> dict:
    """Confirm the broker is up and report the policy it is running under."""
    try:
        response = await client.get('/health', timeout=10)
        response.raise_for_status()
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        print(f'ERROR: broker not reachable at {broker_url} ({exc})', file=sys.stderr)
        print('Start it first:  python -m uvicorn soc_orchestrator:app --port 8500', file=sys.stderr)
        raise SystemExit(1)

    health = response.json()
    if not health.get('authenticated'):
        print(
            f'ERROR: broker rejected the API key in BROKER_API_KEY.\n'
            f'       Set it to a key the broker was started with '
            f'(BROKER_API_KEYS="ai-demo:analyst:<secret>").',
            file=sys.stderr,
        )
        raise SystemExit(1)

    autopilot = health.get('autopilot') or {}
    response = health.get('response') or {}
    llm = health.get('llm') or {}

    print(f'Broker      : {broker_url} (as {(health.get("principal") or {}).get("name")})')
    print(f'Model       : {health.get("model")} @ {llm.get("endpoint") or llm.get("provider")}')
    routes = ', '.join(f'{rule}->{name}' for rule, name in sorted((response.get('routes') or {}).items()))
    print(f'Response    : {routes or "(unrouted)"}{" [DRY RUN]" if response.get("dry_run") else ""}')
    if autopilot.get('enabled'):
        print(
            f'Autopilot   : ON - {"/".join(autopilot.get("decisions") or [])} '
            f'at >= {autopilot.get("min_confidence")}% confidence'
        )
    else:
        print('Autopilot   : OFF - every plan waits for analyst approval')
        print('              (restart the broker with TIER2_AUTOPILOT=1 to auto-execute)')
    print()
    return health


async def run_ai_demo(
    *,
    count: int,
    interval: float,
    broker_url: str,
    seed: int | None,
    reset: bool,
) -> int:
    if reset:
        await reset_demo_data()

    rng = random.Random(seed)
    order = [rng.randrange(len(SCENARIO_TEMPLATES)) for _ in range(count)]

    executed = 0
    pending = 0
    failures = 0

    # This script drives a *separate* broker process, so it cannot mint its own
    # key the way the in-process seeder does — the operator supplies one (R1).
    api_key = (os.getenv('BROKER_API_KEY') or '').strip()
    if not api_key:
        print(
            'ERROR: BROKER_API_KEY is not set. The broker requires an API key on\n'
            '       every ingest, and this script posts over HTTP. Start the broker\n'
            '       with BROKER_API_KEYS="ai-demo:analyst:<secret>" and export the\n'
            '       same secret as BROKER_API_KEY here.',
            file=sys.stderr,
        )
        return 1

    # Generous timeout: one alert = one full LLM generation on the broker.
    async with httpx.AsyncClient(
        base_url=broker_url, timeout=300, headers={'X-API-Key': api_key}
    ) as client:
        await _preflight(client, broker_url)

        print(f'{"#":>3}  {"severity":<9} {"decision":<12} {"src":<6} {"conf":>5}  {"status":<10} {"secs":>6}  signature')
        print('-' * 100)

        for index, scenario_index in enumerate(order, start=1):
            alert, _ = build_scenario(scenario_index, rng, base_time=datetime.now())
            started = time.monotonic()

            try:
                response = await client.post('/splunk-alert', json=alert)
            except httpx.HTTPError as exc:
                failures += 1
                print(f'{index:>3}  request failed: {exc}', file=sys.stderr)
                continue

            elapsed = time.monotonic() - started

            if response.status_code != 201:
                failures += 1
                detail = response.text[:160].replace('\n', ' ')
                print(f'{index:>3}  broker {response.status_code}: {detail}', file=sys.stderr)
                if response.status_code == 502:
                    print('     (502 = LLM inference failed - is Ollama up and the model pulled?)',
                          file=sys.stderr)
                continue

            event = response.json()
            decision = event.get('tier2_decision') or {}
            status = decision.get('approval_status', '?')
            if status == 'PENDING':
                pending += 1
            elif status in ('APPROVED', 'EXECUTING', 'DONE'):
                executed += 1
            elif status == 'FAILED':
                failures += 1

            print(
                f'{index:>3}  {event.get("threat_severity", "?"):<9} '
                f'{decision.get("decision", "?"):<12} '
                f'{decision.get("decision_source", "?"):<6} '
                f'{str(decision.get("confidence", "?")):>4}%  '
                f'{status:<10} {elapsed:>6.1f}  {event.get("signature", "")[:44]}'
            )

            if index < len(order):
                await asyncio.sleep(interval)

    print('-' * 100)
    print(f'{len(order)} alerts | {executed} auto-executed | {pending} awaiting analyst | {failures} failed')
    if pending:
        print('Pending plans are waiting on the dashboard - approve one to see SOAR run.')
    return 1 if failures and not executed else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description='AI test mode: mocked alerts through a real LLM and a real SOAR sink.'
    )
    parser.add_argument('--count', type=int, default=6, help='Number of alerts to send (default: 6)')
    parser.add_argument('--interval', type=float, default=3.0,
                        help='Seconds to wait between alerts (default: 3)')
    parser.add_argument('--broker-url', default=DEFAULT_BROKER,
                        help=f'Running broker base URL (default: {DEFAULT_BROKER})')
    parser.add_argument('--seed', type=int, default=None, help='RNG seed for reproducible scenarios')
    parser.add_argument('--keep', action='store_true',
                        help='Append to existing alerts instead of resetting first')
    args = parser.parse_args()

    if args.count < 1:
        print('count must be >= 1', file=sys.stderr)
        sys.exit(1)
    if args.interval < 0:
        print('interval must be >= 0', file=sys.stderr)
        sys.exit(1)

    try:
        sys.exit(
            asyncio.run(
                run_ai_demo(
                    count=args.count,
                    interval=args.interval,
                    broker_url=args.broker_url.rstrip('/'),
                    seed=args.seed,
                    reset=not args.keep,
                )
            )
        )
    except KeyboardInterrupt:
        print('\nStopped.')


if __name__ == '__main__':
    main()
