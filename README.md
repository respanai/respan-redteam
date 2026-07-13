# Respan Red Team

Open-source red-team engine and CLI for AI agents. It probes an agent through normal chat messages,
adapts its attacks, judges the responses, and produces an OWASP-aligned report.

Only scan systems you own or have permission to test.

## Install

Requires Python 3.11 or newer.

```bash
pip install respan-redteam
```

For development:

```bash
git clone https://github.com/respanai/respan-redteam.git
cd respan-redteam
uv sync
```

## Connect your agent

Create `adapter.py` with a `TARGET`. A target opens conversations, and a chat sends user messages to
your agent:

```python
class Chat:
    def send(self, message: str) -> str:
        return my_agent(message)

    def transcript(self) -> list[dict]:
        return []


class Target:
    label = "my-agent"

    def open(self) -> Chat:
        return Chat()


TARGET = Target()
```

Complete templates are available for a
[`local adapter`](https://github.com/respanai/respan-redteam/blob/main/examples/adapter_local.py)
and a
[`server-owned session`](https://github.com/respanai/respan-redteam/blob/main/examples/adapter_session.py).

## Run

The default remote scan uses Respan's hosted engine:

```bash
respan-redteam auth login
respan-redteam adapter.py -o report.json
```

`auth login` validates your Respan API key and saves it in the operating system credential
manager (macOS Keychain, Windows Credential Manager, or Linux Secret Service). The CLI never
writes the key to a plaintext config file. Use `respan-redteam auth status` or
`respan-redteam auth logout` to inspect or remove it.

For CI and other headless environments, set `RESPAN_API_KEY`. You can alternatively pass
`--api-key`, but environment variables are preferable because command arguments may be retained
in shell history or exposed in process listings.

To run the engine locally, provide an OpenAI-compatible API key:

```bash
export OPENAI_API_KEY=...
respan-redteam adapter.py --local -o report.json
```

From a source checkout, use `uv run respan-redteam`. Run `respan-redteam --help` for output,
retry, CI-grade, and connection options.

## Python API

```python
from respan_redteam import run_campaign
from adapter import TARGET

result = run_campaign(TARGET)
print(result.grade(), result.score())
print(result.to_report())
```

## Extend

Custom prompt attacks, payload carriers, and multi-step strategies can be registered through the
public extension API. See the
[`prompts`](https://github.com/respanai/respan-redteam/tree/main/respan_redteam/prompts),
[`carriers`](https://github.com/respanai/respan-redteam/tree/main/respan_redteam/carriers), and
[`strategies`](https://github.com/respanai/respan-redteam/tree/main/respan_redteam/strategies)
packages.

Local model settings use `OPENAI_API_KEY`, optional `OPENAI_BASE_URL`, and the `RESPAN_MODEL_*`
variables documented in
[`config.py`](https://github.com/respanai/respan-redteam/blob/main/respan_redteam/config.py).

## Development

```bash
just test
```

Licensed under
[Apache 2.0](https://github.com/respanai/respan-redteam/blob/main/LICENSE).
