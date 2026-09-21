"""Does anything in your shell override deploy/.env?  (pilot preparation)

Copyright (c) 2026 Ekrami-Labs. All rights reserved.

    python deploy/check_env.py            # before every `docker compose up`

Docker Compose resolves ``${VAR}`` from the **calling shell first** and from
``--env-file`` second. So a variable left in a terminal from an earlier demo -
``TIER2_AUTOPILOT=1``, ``RESPONSE_DRY_RUN=false`` - silently beats what
``deploy/.env`` says, and nothing reports it: the file reads "dry run", the
container is not. Found the ordinary way: rendering the compose file on a machine
that runs Ollama showed ``OLLAMA_HOST: 0.0.0.0:11434`` (Ollama's own *bind*
variable, exported by its installer) where the broker should have been told the
GPU host.

This prints every such override and exits 1. It reads only the names deploy/.env,
deploy/.env.example and the compose file mention, so an unrelated variable in your
shell is never reported.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Mapping

HERE = Path(__file__).resolve().parent

_ASSIGNMENT = re.compile(r'^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$')


def parse_env_file(text: str) -> Dict[str, str]:
    """``KEY=value`` lines, as compose reads them: comments and blanks ignored, quotes stripped."""
    values: Dict[str, str] = {}
    for line in text.splitlines():
        if line.lstrip().startswith('#'):
            continue
        match = _ASSIGNMENT.match(line)
        if not match:
            continue
        value = match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        values[match.group(1)] = value
    return values


def names_mentioned(*texts: str) -> set:
    """Every setting name the deployment files talk about, commented examples included."""
    found = set()
    for text in texts:
        found |= set(re.findall(r'^#?\s*([A-Z][A-Z0-9_]+)=', text, re.M))
        found |= set(re.findall(r'\$\{([A-Z][A-Z0-9_]*)', text))
    return found


def find_conflicts(env_file: Mapping[str, str], shell: Mapping[str, str], names: Iterable[str]) -> List[str]:
    """Shell variables that compose would prefer over the env file."""
    problems: List[str] = []
    for name in sorted(set(names)):
        if name not in shell:
            continue
        if name not in env_file:
            problems.append(
                f'{name}={shell[name]!r} is set in your shell but not in deploy/.env — '
                f'compose will use your shell\'s value'
            )
        elif shell[name] != env_file[name]:
            problems.append(
                f'{name}: your shell has {shell[name]!r} but deploy/.env has {env_file[name]!r} — '
                f'compose uses your shell\'s'
            )
    return problems


def main() -> int:
    env_path = HERE / '.env'
    if not env_path.exists():
        print('deploy/.env does not exist. Create it first: cp deploy/.env.example deploy/.env')
        return 2
    env_file = parse_env_file(env_path.read_text(encoding='utf-8'))
    names = names_mentioned(
        env_path.read_text(encoding='utf-8'),
        (HERE / '.env.example').read_text(encoding='utf-8'),
        (HERE / 'docker-compose.yml').read_text(encoding='utf-8'),
    )
    problems = find_conflicts(env_file, os.environ, names)
    if problems:
        print('Your shell overrides deploy/.env:\n')
        for problem in problems:
            print(f'  - {problem}')
        print('\nUnset them (or open a clean shell) and run this again. Nothing was started.')
        return 1
    print('OK: nothing in your shell overrides deploy/.env')
    return 0


if __name__ == '__main__':
    sys.exit(main())
