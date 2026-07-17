"""API-key storage for the CLI.

Prefers the operating system credential manager. When that is unavailable, falls
back to a mode-0600 JSON file next to the TOML config:

    ~/.config/respan-redteam/.credentials.json
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import keyring
from keyring.errors import KeyringError

from .user_config import config_path


SERVICE_NAME = "respan-redteam"


class CredentialStoreUnavailable(RuntimeError):
    """Raised when this machine has no usable system credential manager."""


def credential_name(ws_url: str) -> str:
    host = urlsplit(ws_url).hostname
    if not host:
        raise ValueError("the WebSocket URL has no hostname")
    return host.lower()


def credentials_path() -> Path:
    """Sibling of config.toml: ``…/respan-redteam/.credentials.json``."""
    return config_path().parent / ".credentials.json"


def load_stored_api_key(ws_url: str) -> str | None:
    try:
        return keyring.get_password(SERVICE_NAME, credential_name(ws_url))
    except KeyringError as exc:
        raise CredentialStoreUnavailable(str(exc)) from exc


def save_api_key(ws_url: str, api_key: str) -> None:
    name = credential_name(ws_url)
    try:
        keyring.set_password(SERVICE_NAME, name, api_key)
        if keyring.get_password(SERVICE_NAME, name) != api_key:
            raise CredentialStoreUnavailable(
                "the credential backend did not persist the API key"
            )
    except KeyringError as exc:
        raise CredentialStoreUnavailable(str(exc)) from exc


def delete_api_key(ws_url: str) -> bool:
    name = credential_name(ws_url)
    try:
        if keyring.get_password(SERVICE_NAME, name) is None:
            return False
        keyring.delete_password(SERVICE_NAME, name)
    except KeyringError as exc:
        raise CredentialStoreUnavailable(str(exc)) from exc
    return True


def _read_file_store() -> dict[str, str]:
    path = credentials_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in data.items()
        if isinstance(key, str) and isinstance(value, str) and value
    }


def _write_file_store(data: dict[str, str]) -> None:
    path = credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def load_file_api_key(ws_url: str) -> str | None:
    return _read_file_store().get(credential_name(ws_url))


def save_file_api_key(ws_url: str, api_key: str) -> None:
    data = _read_file_store()
    data[credential_name(ws_url)] = api_key
    _write_file_store(data)


def delete_file_api_key(ws_url: str) -> bool:
    data = _read_file_store()
    if credential_name(ws_url) not in data:
        return False
    del data[credential_name(ws_url)]
    if data:
        _write_file_store(data)
    else:
        path = credentials_path()
        try:
            path.unlink(missing_ok=True)
        except OSError:
            _write_file_store({})
    return True


def resolve_api_key(ws_url: str, explicit: str | None = None) -> tuple[str | None, str]:
    """Resolve an API key and report its source without persisting env/flag values."""
    if explicit:
        return explicit, "--api-key"
    environment = os.environ.get("RESPAN_API_KEY") or os.environ.get(
        "RESPAN_REDTEAM_API_KEY"
    )
    if environment:
        return environment, "environment"
    keyring_unavailable = False
    try:
        stored = load_stored_api_key(ws_url)
    except CredentialStoreUnavailable:
        stored = None
        keyring_unavailable = True
    if stored:
        return stored, "system credential store"
    file_key = load_file_api_key(ws_url)
    if file_key:
        return file_key, "credentials file"
    if keyring_unavailable:
        return None, "unavailable credential store"
    return None, "none"
