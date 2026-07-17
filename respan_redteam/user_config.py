"""Non-secret, profile-based configuration for the CLI."""

from __future__ import annotations

import os
import tomllib
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import tomli_w


DEFAULT_SERVER = "https://api.respan.ai"
GRADES = {"A", "B", "C", "D", "F"}
MODEL_KEYS = {
    "model_attacker",
    "model_judge_gate",
    "model_judge_grade",
    "model_recon",
}
BUDGET_TYPES: dict[str, type] = {
    "max_target_probes": int,
    "recon_probes": int,
    "strategy_seed_limit": int,
    "crescendo_max_turns": int,
    "crescendo_max_backtracks": int,
    "judge_success_threshold": float,
}
COMMON_KEYS = {"mode", "output_format", "fail_under"}
HOSTED_KEYS = COMMON_KEYS | {"server"}
LOCAL_KEYS = COMMON_KEYS | {"openai_base_url"} | MODEL_KEYS | {"budget"}
SETTABLE_KEYS = (HOSTED_KEYS | LOCAL_KEYS) - {"budget"} | {
    f"budget.{key}" for key in BUDGET_TYPES
}


class UserConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ProfileConfig:
    name: str
    mode: str = "hosted"
    server: str | None = None
    output_format: str | None = None
    fail_under: str | None = None
    openai_base_url: str | None = None
    model_attacker: str | None = None
    model_judge_gate: str | None = None
    model_judge_grade: str | None = None
    model_recon: str | None = None
    budget: dict[str, int | float] = field(default_factory=dict)

    def display(self) -> dict[str, Any]:
        values = asdict(self)
        values.pop("name")
        return {key: value for key, value in values.items() if value not in (None, {})}


def config_path() -> Path:
    override = os.environ.get("RESPAN_REDTEAM_CONFIG")
    if override:
        return Path(override).expanduser()
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "respan-redteam" / "config.toml"


def read_config() -> dict[str, Any]:
    path = config_path()
    if not path.exists():
        return {}
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise UserConfigError(f"could not read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise UserConfigError(f"{path} must contain a TOML table")
    unknown = set(data) - {"profile", "profiles"}
    if unknown:
        raise UserConfigError(f"unknown top-level setting(s): {', '.join(sorted(unknown))}")
    return data


def selected_profile(data: dict[str, Any], override: str | None = None) -> str:
    name = override or data.get("profile") or "default"
    if not isinstance(name, str) or not name.strip():
        raise UserConfigError("profile must be a non-empty string")
    return name


def load_profile(name: str | None = None) -> ProfileConfig:
    data = read_config()
    selected = selected_profile(data, name)
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        raise UserConfigError("profiles must be a TOML table")
    if selected not in profiles:
        if not profiles and selected == "default":
            return ProfileConfig(name="default", server=DEFAULT_SERVER)
        raise UserConfigError(f"profile {selected!r} does not exist in {config_path()}")
    raw = profiles[selected]
    if not isinstance(raw, dict):
        raise UserConfigError(f"profile {selected!r} must be a TOML table")
    mode = raw.get("mode", "hosted")
    if mode not in ("hosted", "local"):
        raise UserConfigError(f"profile {selected!r}: mode must be 'hosted' or 'local'")
    allowed = HOSTED_KEYS if mode == "hosted" else LOCAL_KEYS
    unknown = set(raw) - allowed
    if unknown:
        setting = ", ".join(sorted(unknown))
        raise UserConfigError(f"profile {selected!r} ({mode}) does not allow: {setting}")
    if mode == "hosted" and not raw.get("server"):
        raw = {**raw, "server": DEFAULT_SERVER}
    if raw.get("output_format") not in (None, "text", "json"):
        raise UserConfigError(f"profile {selected!r}: output_format must be 'text' or 'json'")
    if raw.get("fail_under") not in (None, *sorted(GRADES)):
        raise UserConfigError(f"profile {selected!r}: fail_under must be A, B, C, D, or F")
    for key in ({"server", "openai_base_url"} | MODEL_KEYS):
        if raw.get(key) is not None and not isinstance(raw[key], str):
            raise UserConfigError(f"profile {selected!r}: {key} must be a string")
    budget = raw.get("budget", {})
    if not isinstance(budget, dict):
        raise UserConfigError(f"profile {selected!r}: budget must be a TOML table")
    unknown_budget = set(budget) - set(BUDGET_TYPES)
    if unknown_budget:
        raise UserConfigError(
            f"profile {selected!r}: unknown budget setting(s): "
            f"{', '.join(sorted(unknown_budget))}"
        )
    normalized_budget: dict[str, int | float] = {}
    for key, value in budget.items():
        expected = BUDGET_TYPES[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise UserConfigError(f"profile {selected!r}: budget.{key} must be numeric")
        normalized = expected(value)
        if normalized <= 0:
            raise UserConfigError(f"profile {selected!r}: budget.{key} must be greater than zero")
        normalized_budget[key] = normalized
    values = {key: raw.get(key) for key in ProfileConfig.__dataclass_fields__ if key != "name"}
    values["budget"] = normalized_budget
    return ProfileConfig(name=selected, **values)


def write_config(data: dict[str, Any]) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    try:
        temporary.write_text(tomli_w.dumps(data), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(path)
    except OSError as exc:
        raise UserConfigError(f"could not write {path}: {exc}") from exc


def set_selected_profile(name: str) -> None:
    data = read_config()
    profiles = data.get("profiles", {})
    if name not in profiles:
        raise UserConfigError(f"profile {name!r} does not exist")
    load_profile(name)
    data["profile"] = name
    write_config(data)


def set_profile_value(profile: str, key: str, value: str) -> None:
    if key.lower().endswith("api_key"):
        raise UserConfigError("API keys must use environment variables or the credential manager")
    if key not in SETTABLE_KEYS:
        raise UserConfigError(f"unknown setting {key!r}")
    data = read_config()
    original = deepcopy(data)
    profiles = data.setdefault("profiles", {})
    raw = profiles.setdefault(profile, {"mode": "hosted"})
    if key == "mode":
        if value not in ("hosted", "local"):
            raise UserConfigError("mode must be 'hosted' or 'local'")
        raw["mode"] = value
        incompatible = LOCAL_KEYS - COMMON_KEYS if value == "hosted" else {"server"}
        for field_name in incompatible:
            raw.pop(field_name, None)
    elif key.startswith("budget."):
        budget_key = key.split(".", maxsplit=1)[1]
        expected = BUDGET_TYPES[budget_key]
        try:
            parsed = expected(value)
        except ValueError as exc:
            raise UserConfigError(f"{key} must be a number") from exc
        raw.setdefault("budget", {})[budget_key] = parsed
    else:
        raw[key] = value
    write_config(data)
    try:
        load_profile(profile)
    except UserConfigError:
        write_config(original)
        raise


def unset_profile_value(profile: str, key: str) -> None:
    if key not in SETTABLE_KEYS:
        raise UserConfigError(f"unknown setting {key!r}")
    data = read_config()
    original = deepcopy(data)
    profiles = data.get("profiles", {})
    raw = profiles.get(profile)
    if not isinstance(raw, dict):
        raise UserConfigError(f"profile {profile!r} does not exist")
    if key.startswith("budget."):
        raw.get("budget", {}).pop(key.split(".", maxsplit=1)[1], None)
        if not raw.get("budget"):
            raw.pop("budget", None)
    else:
        raw.pop(key, None)
    write_config(data)
    try:
        load_profile(profile)
    except UserConfigError:
        write_config(original)
        raise


def render_profile(profile: ProfileConfig) -> str:
    return tomli_w.dumps(
        {"profile": profile.name, "profiles": {profile.name: profile.display()}}
    )
