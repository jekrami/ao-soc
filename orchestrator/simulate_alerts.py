"""Real-time SOC simulation: feed varied alerts into soc_matrix.db over time.

Unlike ``seed_demo_alert.py`` (which dumps a batch at once), this trickles
alerts in on a timer so the dashboard's 15s auto-refresh shows incidents
appearing live — closer to a real SOC shift.

Run it in a second terminal while the broker (uvicorn) is already serving
``/api/alerts`` from the same ``soc_matrix.db``:

    python simulate_alerts.py --interval 10 --duration 120

Defaults to ~1-2 alerts every 10s for 2 minutes (no Ollama required).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from datetime import datetime
from typing import Any

import httpx

import soc_orchestrator as broker
from seed_demo_alert import SCENARIO_TEMPLATES, build_scenario, reset_demo_data


async def run_simulation(
    *,
    interval: float,
    duration: float,
    min_per_tick: int,
    max_per_tick: int,
    contain_chance: float,
    seed: int | None,
    reset: bool,
) -> None:
    if reset:
        await reset_demo_data()
    else:
        # Ensure tables exist even if the broker hasn't started yet.
        await broker.init_db()

    rng = random.Random(seed)
    scenario_index = rng.randrange(len(SCENARIO_TEMPLATES))

    pending_llm: dict[str, Any] = {}

    async def mock_call_ollama(_prompt: str) -> str:
        return json.dumps(pending_llm)

    broker.call_ollama = mock_call_ollama
    transport = httpx.ASGITransport(app=broker.app)

    total_created = 0
    total_contained = 0
    start = time.monotonic()
    tick = 0

    print(
        f'Simulating SOC feed: ~{min_per_tick}-{max_per_tick} alert(s) '
        f'every {interval:g}s for {duration:g}s. Press Ctrl+C to stop early.'
    )

    async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
        while time.monotonic() - start < duration:
            tick += 1
            batch = rng.randint(min_per_tick, max_per_tick)
            created_now: list[tuple[str, str, str]] = []

            for _ in range(batch):
                alert, llm = build_scenario(scenario_index, rng, base_time=datetime.now())
                scenario_index = (scenario_index + 1) % len(SCENARIO_TEMPLATES)

                pending_llm.clear()
                pending_llm.update(llm)

                response = await client.post('/splunk-alert', json=alert)
                if response.status_code != 201:
                    print(response.text, file=sys.stderr)
                    sys.exit(1)

                data = response.json()
                alert_id = data['id']
                total_created += 1
                created_now.append((alert_id, llm['threat_severity'], alert['result']['signature']))

                # Occasionally auto-contain an alert to make status metrics move.
                if rng.random() < contain_chance:
                    mitigated = await client.post(f'/api/alerts/{alert_id}/mitigate')
                    if mitigated.status_code == 200:
                        total_contained += 1

            elapsed = time.monotonic() - start
            for alert_id, severity, signature in created_now:
                print(f'[t+{elapsed:5.1f}s] {severity:<8} {alert_id}  {signature}')

            if time.monotonic() - start >= duration:
                break
            await asyncio.sleep(interval)

    print(
        f'\nDone: {total_created} alerts over {time.monotonic() - start:.0f}s '
        f'({total_contained} auto-contained).'
    )


def main() -> None:
    parser = argparse.ArgumentParser(description='Real-time SOC alert simulation (no Ollama).')
    parser.add_argument('--interval', type=float, default=10.0, help='Seconds between batches (default: 10)')
    parser.add_argument('--duration', type=float, default=120.0, help='Total run time in seconds (default: 120)')
    parser.add_argument('--min-per-tick', type=int, default=1, help='Min alerts per batch (default: 1)')
    parser.add_argument('--max-per-tick', type=int, default=2, help='Max alerts per batch (default: 2)')
    parser.add_argument(
        '--contain-chance',
        type=float,
        default=0.2,
        help='Probability each alert is auto-contained (0-1, default: 0.2)',
    )
    parser.add_argument('--seed', type=int, default=None, help='Optional RNG seed for reproducible runs')
    parser.add_argument(
        '--keep',
        action='store_true',
        help='Append to existing alerts instead of resetting first (reset is the default)',
    )
    args = parser.parse_args()

    if args.interval <= 0 or args.duration <= 0:
        print('interval and duration must be positive', file=sys.stderr)
        sys.exit(1)
    if args.min_per_tick < 1 or args.max_per_tick < args.min_per_tick:
        print('require 1 <= min-per-tick <= max-per-tick', file=sys.stderr)
        sys.exit(1)
    if not 0.0 <= args.contain_chance <= 1.0:
        print('contain-chance must be between 0 and 1', file=sys.stderr)
        sys.exit(1)

    try:
        asyncio.run(
            run_simulation(
                interval=args.interval,
                duration=args.duration,
                min_per_tick=args.min_per_tick,
                max_per_tick=args.max_per_tick,
                contain_chance=args.contain_chance,
                seed=args.seed,
                reset=not args.keep,
            )
        )
    except KeyboardInterrupt:
        print('\nSimulation stopped.')


if __name__ == '__main__':
    main()
