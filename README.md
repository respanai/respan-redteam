# Respan Red Team

Adaptive security testing for AI agents.

Respan profiles your agent, chooses attack strategies, adapts after refusals, and
produces an evidence-backed, OWASP-aligned report.

Only scan systems you own or are authorized to test.

## Quickstart

Requires Python 3.11+ and a [Respan API key](https://platform.respan.ai/platform/api-keys).

### 1. Install

```bash
pip install respan-redteam
```

### 2. Sign in

Get an API key at [platform.respan.ai/platform/api-keys](https://platform.respan.ai/platform/api-keys), then:

```bash
respan-redteam auth login
```

Paste your API key when prompted (characters echo as `*`). The key is stored in
your OS credential manager, or in `~/.config/respan-redteam/.credentials.json` if
that store is unavailable.

For CI / headless use:

```bash
export RESPAN_API_KEY="..."
```

### 3. Connect your agent

Paste this into your coding agent (Cursor, Claude Code, Codex, etc.):

```text
Fetch https://www.respan.ai/redteam-setup.txt
and follow it to create adapter.py for my agent, then tell me how to run the scan.
```

That setup guide walks the agent through writing a small `adapter.py` that talks
to your system. Prefer that over hand-writing the protocol.

### 4. Scan

```bash
respan-redteam scan adapter.py
```

```bash
respan-redteam scan adapter.py --output report.json
```

Progress goes to stderr; the report goes to stdout or `--output`.

## Commands

```text
respan-redteam auth login|status|logout
respan-redteam config show|edit|path|set|use
respan-redteam scan ADAPTER [--local] [-o PATH] [--fail-under B]
```

Run `respan-redteam <command> --help` for options.

## Hosted vs local

By default the attack engine runs on Respan (`https://api.respan.ai`). Your
adapter stays on your machine and only exchanges user messages / replies.

```bash
export OPENAI_API_KEY="..."
respan-redteam scan adapter.py --local --output report.json
```

Local mode runs the open-source engine on your machine. Non-secret settings live
in `~/.config/respan-redteam/config.toml` (`respan-redteam config edit`).

## CI

```bash
RESPAN_API_KEY="$RESPAN_API_KEY" \
  respan-redteam scan adapter.py \
  --output redteam-report.json \
  --fail-under B \
  --quiet
```

Exit code `4` means the grade fell below `--fail-under`.

## Examples & API

- [`examples/adapter_local.py`](https://github.com/respanai/respan-redteam/blob/main/examples/adapter_local.py) — client-owned history
- [`examples/adapter_session.py`](https://github.com/respanai/respan-redteam/blob/main/examples/adapter_session.py) — server-owned sessions
- [`SETUP`](https://github.com/respanai/respan-redteam/blob/main/SETUP) — full adapter brief for coding agents

```python
from respan_redteam import EngineConfig, LLMConfig, run_campaign
from adapter import TARGET

result = run_campaign(
    TARGET,
    config=EngineConfig(llm=LLMConfig(api_key="...", model_attacker="gpt-4.1")),
)
print(result.grade(), result.to_report())
```

## Development

```bash
git clone https://github.com/respanai/respan-redteam.git
cd respan-redteam
uv sync
just test
```

Licensed under [Apache 2.0](https://github.com/respanai/respan-redteam/blob/main/LICENSE).
