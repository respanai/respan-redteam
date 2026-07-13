# Respan Red Team

Adaptive security testing for AI agents.

Respan talks to your agent like an attacker would: it profiles the target, chooses relevant attack
strategies, adapts after refusals, verifies suspected breaches, and produces an evidence-backed,
OWASP-aligned report.

Only scan systems you own or are authorized to test.

## Quickstart

Respan requires Python 3.11 or newer and a Respan API key.

### 1. Install the CLI

```bash
pip install respan-redteam
```

### 2. Sign in

```bash
respan-redteam auth login
```

Paste your API key when prompted. Respan validates it and stores it in your operating system's
credential manager—not in a plaintext configuration file.

For CI or another headless environment, use an environment variable instead:

```bash
export RESPAN_API_KEY="..."
```

### 3. Connect your agent

Create `adapter.py`. The adapter needs to open a fresh conversation and send one user message at a
time:

```python
class Chat:
    def __init__(self):
        self.messages = []

    def send(self, message: str) -> str:
        # Replace this with your SDK, HTTP request, or agent invocation.
        reply = call_my_agent(message, history=self.messages)
        self.messages.extend([
            {"role": "user", "content": message},
            {"role": "assistant", "content": reply},
        ])
        return reply

    def transcript(self) -> list[dict]:
        return list(self.messages)


class Target:
    label = "my-agent"

    def open(self) -> Chat:
        return Chat()


TARGET = Target()
```

`open()` must return a new conversation. This prevents one attack strategy from contaminating the
state of another. If your server owns conversation history, use the
[`adapter_session.py`](https://github.com/respanai/respan-redteam/blob/main/examples/adapter_session.py)
example instead.

### 4. Run a scan

```bash
respan-redteam scan adapter.py
```

Save the report as JSON:

```bash
respan-redteam scan adapter.py --output report.json
```

The output format is inferred from the filename. Progress is written to stderr, so stdout remains
safe to pipe into another command.

## Commands

```text
respan-redteam auth login               Validate and save an API key
respan-redteam auth status              Show the active credential source
respan-redteam auth logout              Remove the saved API key
respan-redteam config show              Show the effective profile
respan-redteam config edit              Edit non-secret settings
respan-redteam scan ADAPTER              Run a hosted campaign
respan-redteam scan ADAPTER --local      Run the engine on this machine
```

Run `respan-redteam <command> --help` for command-specific options.

### Useful scan options

```text
-o, --output PATH       Write the report to a file
-f, --format FORMAT     Select text or JSON output
-q, --quiet             Hide progress output
--fail-under GRADE      Fail CI when the grade is below A, B, C, D, or F
--server URL            Use a self-hosted Respan server
--profile NAME          Use a named configuration profile
--local                 Run the engine locally
```

The pre-0.1.2 form, `respan-redteam adapter.py`, remains supported for compatibility. New scripts
should use the explicit `scan` command.

## Configuration profiles

Non-secret settings live in a TOML file. Print its location with:

```bash
respan-redteam config path
```

The default is `~/.config/respan-redteam/config.toml` (or
`$XDG_CONFIG_HOME/respan-redteam/config.toml`). Use `respan-redteam config edit` to create and open
it, or manage individual values from the command line:

```bash
respan-redteam config set server https://redteam.respan.ai
respan-redteam config set mode local --profile local
respan-redteam config set openai_base_url http://localhost:11434/v1 --profile local
respan-redteam config set model_attacker my-model --profile local
respan-redteam config set budget.max_target_probes 40 --profile local
respan-redteam config use local
respan-redteam config show
```

A hosted profile and a local profile accept different settings:

```toml
profile = "default"

[profiles.default]
mode = "hosted"
server = "https://redteam.respan.ai"
output_format = "text"
fail_under = "B"

[profiles.local]
mode = "local"
openai_base_url = "http://localhost:11434/v1"
model_attacker = "my-model"
model_judge_gate = "my-fast-model"
model_judge_grade = "my-model"
model_recon = "my-model"

[profiles.local.budget]
max_target_probes = 40
recon_probes = 9
crescendo_max_turns = 6
```

`server` is valid only in a hosted profile. Model and budget settings are valid only in a local
profile; mixed profiles are rejected rather than silently ignoring settings.

API keys are never written to TOML. `RESPAN_API_KEY` uses the environment or operating-system
credential manager, while `OPENAI_API_KEY` remains environment-only.

Configuration precedence is: CLI flag, environment variable, selected profile, built-in default.
Use `--profile NAME` to select a profile for one scan without changing the default.

## What happens during a scan?

1. **Reconnaissance** identifies the agent's role, tools, exposed capabilities, guardrails, and
   refusal patterns.
2. **Strategies** choose a campaign plan for each relevant security objective, including broad
   exploration, multi-turn escalation, guardrail bypass, exfiltration, and tool abuse.
3. **Attacks** turn an objective into a concrete adversarial message using techniques such as
   authority framing, role-play, developer-mode claims, or refusal suppression.
4. **Carriers** transform an attack without changing its intent. Built-in carriers include Base64,
   ROT13, Caesar, Atbash, reversed text, and leetspeak.
5. **Judging** independently classifies each response as refused, partially successful, or breached.
6. **Reporting** preserves the prompt, response, technique, severity, and evidence for every
   confirmed finding.

The campaign shares one probe budget and adapts based on previous results instead of replaying a
fixed list of jailbreak prompts.

## Hosted versus local execution

The default `scan` command uses Respan's hosted attack engine. Your adapter still runs on your
machine, while the CLI opens an outbound authenticated connection. The engine sends test messages
to the adapter; the adapter invokes your agent and returns its responses.

To run the open-source engine entirely on your machine:

```bash
export OPENAI_API_KEY="..."
respan-redteam scan adapter.py --local --output report.json
```

Local execution supports `OPENAI_BASE_URL` for OpenAI-compatible providers. Model selection and
budget settings are documented in
[`respan_redteam/config.py`](https://github.com/respanai/respan-redteam/blob/main/respan_redteam/config.py).

## CI example

```bash
RESPAN_API_KEY="$RESPAN_API_KEY" \
  respan-redteam scan adapter.py \
  --output redteam-report.json \
  --fail-under B \
  --quiet
```

The CLI exits with code `4` when the report grade is below the requested threshold. Connection,
adapter, and report failures use distinct non-zero exit codes, making the command suitable for CI
gates.

## More adapter examples

- [`examples/adapter_local.py`](https://github.com/respanai/respan-redteam/blob/main/examples/adapter_local.py):
  a complete in-memory target with
  client-owned conversation history.
- [`examples/adapter_session.py`](https://github.com/respanai/respan-redteam/blob/main/examples/adapter_session.py):
  a stateful service where the server owns the conversation.

An adapter may export `TARGET`, `build_target()`, or another symbol selected with `--symbol`.

## Python API

Local campaigns can also be started directly from Python:

```python
from respan_redteam import run_campaign
from adapter import TARGET

result = run_campaign(TARGET)
print(result.grade(), result.score())
print(result.to_report())
```

## Extend the engine

The extension API supports custom attacks, carriers, and multi-step strategies:

- [`respan_redteam/prompts`](https://github.com/respanai/respan-redteam/tree/main/respan_redteam/prompts):
  concrete attack framings
- [`respan_redteam/carriers`](https://github.com/respanai/respan-redteam/tree/main/respan_redteam/carriers):
  reusable payload transformations
- [`respan_redteam/strategies`](https://github.com/respanai/respan-redteam/tree/main/respan_redteam/strategies):
  campaign behavior and scheduling

## Development

```bash
git clone https://github.com/respanai/respan-redteam.git
cd respan-redteam
uv sync
just test
```

Respan Red Team is licensed under the
[Apache License 2.0](https://github.com/respanai/respan-redteam/blob/main/LICENSE).
