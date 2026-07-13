"""API-key storage for the CLI using the operating system credential manager."""

from __future__ import annotations

import os
from urllib.parse import urlsplit

import keyring
from keyring.errors import KeyringError


SERVICE_NAME = "respan-redteam"


class CredentialStoreUnavailable(RuntimeError):
    """Raised when this machine has no usable system credential manager."""


def credential_name(ws_url: str) -> str:
    host = urlsplit(ws_url).hostname
    if not host:
        raise ValueError("the WebSocket URL has no hostname")
    return host.lower()


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


def resolve_api_key(ws_url: str, explicit: str | None = None) -> tuple[str | None, str]:
    """Resolve an API key and report its source without persisting env/flag values."""
    if explicit:
        return explicit, "--api-key"
    environment = os.environ.get("RESPAN_API_KEY") or os.environ.get(
        "RESPAN_REDTEAM_API_KEY"
    )
    if environment:
        return environment, "environment"
    try:
        return load_stored_api_key(ws_url), "system credential store"
    except CredentialStoreUnavailable:
        return None, "unavailable credential store"
