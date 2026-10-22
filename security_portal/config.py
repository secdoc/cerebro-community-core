from __future__ import annotations

import json
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse


class ConfigError(ValueError):
    """Raised when portal configuration violates the read-only contract."""


_ALLOWED_CONNECTORS = {"json_file", "http_json", "static"}
_ALLOWED_STATES = {"healthy", "degraded", "stale", "unavailable", "unauthorized", "unknown", "planned"}


def _web_url(value: str, field: str) -> None:
    try:
        parsed = urlparse(value)
        host = parsed.hostname or ''
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field} has invalid URL") from exc
    if parsed.scheme != 'https' or not host or parsed.username or parsed.password or parsed.query or parsed.fragment or not re.fullmatch(r'[A-Za-z0-9.-]+', host):
        raise ConfigError(f"{field} requires a credential-free HTTPS URL")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ConfigError(f"{field} must not target an IP literal in a non-public network")
    if host.lower() in {'localhost', 'localhost.localdomain'} or host.lower().endswith(('.local', '.internal', '.home')):
        raise ConfigError(f"{field} requires an explicitly trusted DNS name")
    if port is not None and not 1 <= port <= 65535:
        raise ConfigError(f"{field} must be an http or https URL without embedded credentials")


def _origin(value: str) -> str:
    parsed = urlparse(value)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme.lower()}://{(parsed.hostname or '').lower()}:{port}"


def load_config(path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError("portal configuration is unreadable") from exc
    if not isinstance(config, dict):
        raise ConfigError("portal configuration must be an object")
    portal = config.get("portal")
    integrations = config.get("integrations")
    if not isinstance(portal, dict) or not isinstance(portal.get("title"), str):
        raise ConfigError("portal.title is required")
    refresh = portal.get("refresh_seconds", 60)
    if not isinstance(refresh, int) or not 10 <= refresh <= 3600:
        raise ConfigError("portal.refresh_seconds must be between 10 and 3600")
    if not isinstance(integrations, list):
        raise ConfigError("integrations must be a list")
    seen: set[str] = set()
    for spec in integrations:
        if not isinstance(spec, dict):
            raise ConfigError("each integration must be an object")
        integration_id = spec.get("id")
        if not isinstance(integration_id, str) or not integration_id or integration_id in seen:
            raise ConfigError("integration ids must be unique non-empty strings")
        seen.add(integration_id)
        if not isinstance(spec.get("name"), str) or not isinstance(spec.get("category"), str):
            raise ConfigError(f"integration {integration_id} requires name and category")
        connector = spec.get("connector")
        if connector not in _ALLOWED_CONNECTORS:
            raise ConfigError(f"integration {integration_id} has unsupported connector")
        max_age = spec.get("max_age_seconds")
        if not isinstance(max_age, int) or max_age <= 0:
            raise ConfigError(f"integration {integration_id} requires positive max_age_seconds")
        if spec.get('analytics_paths'):
            raise ConfigError('analytics publication is excluded in the public package')
        for field in ("summary_paths",):
            paths = spec.get(field, {})
            if not isinstance(paths, dict) or not all(
                isinstance(key, str) and key and isinstance(value, str) and value
                for key, value in paths.items()
            ):
                raise ConfigError(f"integration {integration_id} has invalid {field}")
        for field in ("record_count_path", "collection_duration_ms_path"):
            value = spec.get(field)
            if value is not None and (not isinstance(value, str) or not value):
                raise ConfigError(f"integration {integration_id} has invalid {field}")
        source_owner = spec.get("source_owner")
        if source_owner is not None and (not isinstance(source_owner, str) or not source_owner):
            raise ConfigError(f"integration {integration_id} has invalid source_owner")
        cadence = spec.get("collection_cadence_seconds")
        if cadence is not None and (
            not isinstance(cadence, int) or isinstance(cadence, bool) or cadence <= 0
        ):
            raise ConfigError(f"integration {integration_id} has invalid collection_cadence_seconds")
        state_map = spec.get("state_map", {})
        if not isinstance(state_map, dict) or not all(
            isinstance(key, str) and key and key == key.lower()
            and isinstance(value, str) and value in _ALLOWED_STATES
            for key, value in state_map.items()
        ):
            raise ConfigError(f"integration {integration_id} has invalid state_map")
        if spec.get("deep_link") is not None:
            _web_url(spec["deep_link"], "deep_link")
        if connector == "json_file" and not isinstance(spec.get("path"), str):
            raise ConfigError(f"integration {integration_id} requires path")
        if connector == 'json_file' and (not Path(spec['path']).is_absolute() or '..' in Path(spec['path']).parts):
            raise ConfigError('snapshot requires an absolute safe path')
        if connector == "http_json":
            _web_url(spec.get("url", ""), "url")
            if spec.get("method", "GET") != "GET":
                raise ConfigError("http_json connectors permit GET only")
            if spec.get('header_env') or spec.get('ca_file') or spec.get('timeout_seconds', 10) != 10:
                raise ConfigError('custom headers, CA overrides and timeouts are excluded')
            allowed_origins = spec.get("allowed_origins")
            if not isinstance(allowed_origins, list) or not allowed_origins:
                raise ConfigError(f"integration {integration_id} requires allowed_origins")
            for allowed in allowed_origins:
                if not isinstance(allowed, str):
                    raise ConfigError(f"integration {integration_id} has invalid allowed_origins")
                _web_url(allowed, "allowed_origins")
            if _origin(spec["url"]) not in {_origin(value) for value in allowed_origins}:
                raise ConfigError(f"integration {integration_id} URL is outside allowed_origins")
        if connector == "static" and spec.get("state", "unknown") not in _ALLOWED_STATES:
            raise ConfigError(f"integration {integration_id} has invalid static state")
    return config
