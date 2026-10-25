"""Broker checks split out of test_broker.py. Import after env vars are set."""
from __future__ import annotations

from tests.harness import *  # noqa: F401,F403

def check_deployment_drift() -> None:
    """A setting an operator is told to set must be a setting something reads.

    The deployment files and the runbook once told operators to set ``LLM_ENDPOINT``,
    ``LLM_MODEL``, ``ALLOWED_ORIGINS`` and ``DASHBOARD_API_KEYS`` - four names that
    nothing read. Nothing failed: the container dialled itself for a model, the
    measured model was never selected, and the dashboard minted a one-time key into a
    log. Worse, compose forwards only the variables it lists, so every connector,
    threat-intel and case-sync line the example file invited an operator to uncomment
    never reached the broker at all. This is the same failure as every other silent
    one in this project, so it is checked, not trusted: every name in the shipped
    deployment files, the runbook and the README must be a name the code reads.
    """
    import glob
    import re

    root = os.path.join('..')
    if not os.path.isdir(os.path.join(root, 'deploy')):
        # Run from inside the image (the runbook asks for that): the deployment
        # files are not shipped in it, and this check is about them.
        print('SKIP: check_deployment_drift - the deploy/ directory is not present')
        return

    def read(*parts):
        with open(os.path.join(root, *parts), encoding='utf-8') as handle:
            return handle.read()

    token = re.compile(r"""['"]([A-Z][A-Z0-9_]{2,})['"]""")
    read_by_broker = set()
    for path in glob.glob('*.py') + glob.glob('*/*.py'):
        if os.path.basename(path).startswith('test_'):
            continue
        with open(path, encoding='utf-8') as handle:
            read_by_broker |= set(token.findall(handle.read()))
    read_by_ui_api = {'PORT'}
    for path in (
        glob.glob(os.path.join(root, 'backend', '*.js'))
        + glob.glob(os.path.join(root, 'backend', 'routes', '*.js'))
    ):
        with open(path, encoding='utf-8') as handle:
            source = handle.read()
        read_by_ui_api |= set(re.findall(r'process\.env\.([A-Z][A-Z0-9_]+)', source))
        read_by_ui_api |= set(re.findall(r"process\.env\[['\"]([A-Z][A-Z0-9_]+)['\"]\]", source))
    for path in (
        glob.glob(os.path.join(root, 'frontend', 'src', '**', '*.ts'), recursive=True)
        + glob.glob(os.path.join(root, 'frontend', 'src', '**', '*.tsx'), recursive=True)
    ):
        with open(path, encoding='utf-8') as handle:
            source = handle.read()
        read_by_ui_api |= set(re.findall(r'import\.meta\.env\.([A-Z][A-Z0-9_]+)', source))

    compose = read('deploy', 'docker-compose.yml')
    env_example = read('deploy', '.env.example')

    # --- what the compose file sets, service by service ---
    blocks = {}
    for match in re.finditer(r'^  ([a-z][a-z-]*):\s*$(.*?)(?=^  [a-z][a-z-]*:\s*$|^[a-z]+:|\Z)', compose, re.M | re.S):
        blocks[match.group(1)] = match.group(2)
    assert {'broker', 'ui-api', 'dashboard'} <= set(blocks), sorted(blocks)
    env_keys = {
        name: set(re.findall(r'^      ([A-Z][A-Z0-9_]+):', blocks[name], re.M))
        for name in ('broker', 'ui-api')
    }
    interpolated = set(re.findall(r'\$\{([A-Z][A-Z0-9_]*)', compose))

    problems = []
    # Compose reads ${VAR} from the calling shell before --env-file. These are
    # names other software exports there (Ollama's installer sets OLLAMA_HOST as
    # a *bind* address), so interpolating them replaces an operator's setting
    # with somebody else's value, silently.
    for name in sorted(interpolated & {'OLLAMA_HOST', 'OLLAMA_PORT', 'OLLAMA_MODELS', 'HOME', 'PATH', 'USER'}):
        problems.append(
            f'compose interpolates ${{{name}}}, a name other software exports into the shell, '
            f'and compose prefers the shell to deploy/.env'
        )
    for name in sorted(env_keys['broker'] - read_by_broker):
        problems.append(f'compose sets {name} on the broker, but nothing in orchestrator/ reads it')
    for name in sorted(env_keys['ui-api'] - read_by_ui_api):
        problems.append(f'compose sets {name} on the ui-api, but nothing in backend/ reads it')

    # --- what the example file offers, commented or not ---
    offered = set(re.findall(r'^#?\s*([A-Z][A-Z0-9_]+)=', env_example, re.M))
    indirect = set(re.findall(r'^#?\s*CONNECTOR_[A-Z0-9_]+_(?:TOKEN|PASSWORD)_ENV=([A-Z][A-Z0-9_]*)', env_example, re.M))
    for name in sorted(interpolated - offered):
        problems.append(f'compose interpolates ${{{name}}}, which deploy/.env.example never offers')
    for name in sorted(offered):
        if name in indirect or name in interpolated or name.startswith('CONNECTOR_'):
            continue
        if name not in read_by_broker | read_by_ui_api:
            problems.append(f'deploy/.env.example offers {name}, but nothing reads it')
    # The broker only sees what compose forwards. Connector, intel and case-sync
    # settings are open-ended (a secret's variable is named by another setting),
    # so it must forward the whole file rather than a list that goes stale.
    if not re.search(r'^\s+env_file:', blocks['broker'], re.M):
        problems.append(
            'the broker does not receive deploy/.env, so every CONNECTOR_*, MISP_*, THEHIVE_* and '
            'CASE_SYNC_* line an operator uncomments would never reach it'
        )

    # --- the runbook's code blocks ---
    runbook = read('docs', 'PILOT-RUNBOOK.md')
    allowed = read_by_broker | read_by_ui_api | interpolated | indirect
    for block in re.findall(r'```[a-z]*\n(.*?)```', runbook, re.S):
        for name in re.findall(r'^([A-Z][A-Z0-9_]+)=', block, re.M):
            if name.startswith('CONNECTOR_') or name in allowed:
                continue
            problems.append(f'docs/PILOT-RUNBOOK.md tells operators to set {name}, but nothing reads it')
    for name in sorted(set(re.findall(r'`(ao_soc_[a-z0-9_]+)', runbook))):
        with open('metrics.py', encoding='utf-8') as handle:
            if name not in handle.read():
                problems.append(f'docs/PILOT-RUNBOOK.md names the metric {name}, which metrics.py does not define')

    # --- the README's own environment table ---
    with open('README.md', encoding='utf-8') as handle:
        readme = handle.read()
    table = readme.split('## Environment', 1)[1].split('\n## ', 1)[0]
    for name in re.findall(r'^\| `([A-Z][A-Z0-9_]+)`', table, re.M):
        if name not in read_by_broker:
            problems.append(f'orchestrator/README.md documents {name}, which nothing reads')

    # --- an image tag that lags the code it ships ---
    version = read('VERSION').strip()
    for image, tag in re.findall(r'image:\s*(\S+):(\S+)', compose):
        if tag != version:
            problems.append(f'compose builds {image}:{tag}, but VERSION is {version}')

    assert not problems, 'deployment drift:\n  - ' + '\n  - '.join(problems)


def check_unread_settings() -> None:
    """A setting that is set and read by nothing is reported, with what was probably meant."""
    import preflight

    wrong = {
        'LLM_ENDPOINT': 'OLLAMA_HOST', 'LLM_MODEL': 'MODEL_NAME',
        'ALLOWED_ORIGINS': 'BROKER_CORS_ORIGINS',
        'DASHBOARD_API_KEYS': 'AUTH_JWT_PUBLIC_KEY_FILE',
    }
    innocent = {
        'OLLAMA_MODELS': '/models',        # Ollama's own server setting, on the same host
        'BROKER_URL': 'http://127.0.0.1',  # read by the UI API and the demo scripts
        'CONNECTOR_FIREWALL_URL': 'https://fw',
    }
    added = {**wrong, **innocent, 'TIER2_AUTOPILOT_ENABLED': '1'}
    saved = {name: os.environ.get(name) for name in added}
    try:
        for name in added:
            os.environ.pop(name, None)
        assert preflight.unread_settings() == [], preflight.unread_settings()

        os.environ.update(added)
        found = preflight.unread_settings()
        for name, meant in wrong.items():
            line = next((item for item in found if item.startswith(name + ' ')), None)
            assert line and meant in line, (name, found)
        # A misspelling of one of our own settings is caught by its prefix and names the real one.
        typo = next((item for item in found if item.startswith('TIER2_AUTOPILOT_ENABLED ')), '')
        assert 'did you mean TIER2_AUTOPILOT' in typo, typo
        # ...and somebody else's variable in the same environment is left alone.
        for name in innocent:
            assert not any(item.startswith(name + ' ') for item in found), (name, found)

        # It is part of the start-up report, so it lands on /health and in the log.
        assert any('LLM_ENDPOINT' in problem for problem in preflight.startup_problems())
        assert preflight.preflight_report()['ok'] is False
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    assert not any(item.startswith('LLM_ENDPOINT ') for item in preflight.unread_settings())


def check_deploy_env_checker() -> None:
    """deploy/check_env.py: a shell variable that compose would prefer to deploy/.env is reported."""
    import types

    path = os.path.join('..', 'deploy', 'check_env.py')
    if not os.path.exists(path):
        print('SKIP: check_deploy_env_checker - deploy/check_env.py is not present')
        return
    # exec rather than import: importing would leave a __pycache__ in deploy/.
    checker = types.ModuleType('check_env')
    checker.__file__ = os.path.abspath(path)
    with open(path, encoding='utf-8') as handle:
        exec(compile(handle.read(), path, 'exec'), checker.__dict__)

    env_file = checker.parse_env_file(
        '# comment\nRESPONSE_DRY_RUN=true\nTIER2_AUTOPILOT="false"\nexport LOG_LEVEL=INFO\n# COMMENTED=1\n\nnot a setting\n'
    )
    assert env_file == {'RESPONSE_DRY_RUN': 'true', 'TIER2_AUTOPILOT': 'false', 'LOG_LEVEL': 'INFO'}, env_file

    names = checker.names_mentioned('RESPONSE_DRY_RUN=true\n# TI_PROVIDER=misp\n', 'x: ${MODEL_NAME:-q}\n')
    assert names == {'RESPONSE_DRY_RUN', 'TI_PROVIDER', 'MODEL_NAME'}, names

    # Agreement is not a conflict; disagreement and absence are.
    assert checker.find_conflicts(env_file, {'RESPONSE_DRY_RUN': 'true'}, names) == []
    found = checker.find_conflicts(
        env_file,
        {'RESPONSE_DRY_RUN': 'false', 'TI_PROVIDER': 'misp', 'MODEL_NAME': 'x', 'UNRELATED_TOOL': '1'},
        names | {'TIER2_AUTOPILOT'},
    )
    assert any(item.startswith('RESPONSE_DRY_RUN:') and "'false'" in item and "'true'" in item for item in found), found
    # In the shell but not in the file: compose still uses it.
    assert any(item.startswith("TI_PROVIDER='misp'") and 'not in deploy/.env' in item for item in found), found
    # A variable the deployment files never mention is nobody's business.
    assert not any('UNRELATED_TOOL' in item for item in found), found
    # The real example must not itself trip the checker on a clean shell.
    with open(os.path.join('..', 'deploy', '.env.example'), encoding='utf-8') as handle:
        example = handle.read()
    assert checker.find_conflicts(checker.parse_env_file(example), {}, checker.names_mentioned(example)) == []


def check_endpoint_resolution() -> None:
    """OLLAMA_HOST is Ollama's *bind* variable; users routinely set 0.0.0.0."""
    assert llm._build_ollama_endpoint.__module__ == 'llm'
    for bind in ('0.0.0.0', '0.0.0.0:11434', '::'):
        os.environ['OLLAMA_HOST'] = bind
        importlib.reload(llm)
        assert llm.OLLAMA_ENDPOINT.startswith('http://localhost:'), llm.OLLAMA_ENDPOINT
    os.environ['OLLAMA_HOST'] = 'gpu-box:9000'
    importlib.reload(llm)
    assert llm.OLLAMA_ENDPOINT == 'http://gpu-box:9000/api/generate', llm.OLLAMA_ENDPOINT
    os.environ.pop('OLLAMA_HOST', None)
    importlib.reload(llm)


async def check_empty_response_raises() -> None:
    """A thinking model can return an empty `response` with a full `thinking`.

    Handing the Ollama envelope downstream would parse as valid JSON and every
    normalizer would silently default — the pipeline would report success while
    the model contributed nothing.
    """
    envelope = {
        'model': 'qwen3.5:latest', 'created_at': 'now', 'response': '',
        'thinking': 'a lot of reasoning', 'done': True, 'done_reason': 'length',
        'eval_count': 512,
    }

    class _Response:
        status_code = 200

        def raise_for_status(self): return None

        def json(self): return envelope

    class _Client:
        async def __aenter__(self): return self

        async def __aexit__(self, *_): return False

        async def post(self, *_args, **_kwargs): return _Response()

    original = llm.httpx.AsyncClient
    llm.httpx.AsyncClient = lambda *a, **k: _Client()
    try:
        # Caught off the module: check_endpoint_resolution reloads llm, so the
        # class object bound at import time is no longer the one raised.
        await llm.call_ollama('prompt')
    except llm.LlmEmptyResponse as exc:
        assert 'OLLAMA_THINK=false' in str(exc), str(exc)
    else:
        raise AssertionError('empty model response must raise, not return the envelope')
    finally:
        llm.httpx.AsyncClient = original

