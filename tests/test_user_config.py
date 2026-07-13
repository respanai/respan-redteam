"""Offline tests for profile configuration and strict hosted/local separation."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from respan_redteam.user_config import (
    UserConfigError,
    config_path,
    load_profile,
    read_config,
    set_profile_value,
    set_selected_profile,
)


def _config_environment(root: str):
    return patch.dict(
        os.environ,
        {"RESPAN_REDTEAM_CONFIG": str(Path(root) / "config.toml")},
        clear=False,
    )


def test_missing_file_produces_a_hosted_default():
    with tempfile.TemporaryDirectory() as root, _config_environment(root):
        profile = load_profile()
        assert profile.mode == "hosted"
        assert profile.server == "https://redteam.respan.ai"


def test_local_profile_rejects_server_and_hosted_profile_rejects_models():
    with tempfile.TemporaryDirectory() as root, _config_environment(root):
        path = config_path()
        path.write_text(
            '[profiles.local]\nmode = "local"\nserver = "http://localhost:8000"\n',
            encoding="utf-8",
        )
        try:
            load_profile("local")
            assert False, "local profile should reject server"
        except UserConfigError as exc:
            assert "does not allow: server" in str(exc)
        path.write_text(
            '[profiles.default]\nmode = "hosted"\nmodel_attacker = "model"\n',
            encoding="utf-8",
        )
        try:
            load_profile("default")
            assert False, "hosted profile should reject model settings"
        except UserConfigError as exc:
            assert "model_attacker" in str(exc)


def test_mode_transition_removes_incompatible_settings():
    with tempfile.TemporaryDirectory() as root, _config_environment(root):
        set_profile_value("default", "server", "https://example.com")
        set_profile_value("default", "mode", "local")
        set_profile_value("default", "openai_base_url", "http://localhost:11434/v1")
        profile = load_profile("default")
        assert profile.mode == "local" and profile.server is None
        assert profile.openai_base_url == "http://localhost:11434/v1"


def test_invalid_mixed_setting_is_rolled_back():
    with tempfile.TemporaryDirectory() as root, _config_environment(root):
        set_profile_value("default", "server", "https://example.com")
        try:
            set_profile_value("default", "model_attacker", "model")
            assert False, "hosted profile should reject local settings"
        except UserConfigError:
            pass
        assert "model_attacker" not in read_config()["profiles"]["default"]


def test_budget_values_are_typed_and_api_keys_are_forbidden():
    with tempfile.TemporaryDirectory() as root, _config_environment(root):
        set_profile_value("local", "mode", "local")
        set_profile_value("local", "budget.max_target_probes", "20")
        assert load_profile("local").budget["max_target_probes"] == 20
        try:
            set_profile_value("local", "openai_api_key", "secret")
            assert False, "secrets must not be written to TOML"
        except UserConfigError as exc:
            assert "API keys" in str(exc)


def test_selecting_a_profile_requires_it_to_exist():
    with tempfile.TemporaryDirectory() as root, _config_environment(root):
        set_profile_value("local", "mode", "local")
        set_selected_profile("local")
        assert load_profile().name == "local"


def main():
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} passed")


if __name__ == "__main__":
    main()
