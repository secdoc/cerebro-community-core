from __future__ import annotations

import json
import math
import os
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from .model import classify_snapshot


_MISSING = object()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so credentials never cross an unreviewed target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def dotted_get(document: Any, path: str | None, default: Any = None) -> Any:
    if not path:
        return default
    value = document
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return default
    return value


def _summary(document: dict, paths: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for label, path in paths.items():
        value = dotted_get(document, path, _MISSING)
        if value is _MISSING:
            continue
        if value is None or isinstance(value, (bool, int)):
            result[label] = value
        elif isinstance(value, float) and math.isfinite(value):
            result[label] = value
        elif isinstance(value, str) and len(value) <= 256 and all(32 <= ord(c) < 127 for c in value):
            result[label] = value
    return result


def _analytics(document: dict, paths: dict[str, str]) -> dict[str, Any]:
    """Copy only explicitly allowlisted, JSON-compatible aggregate structures."""
    result: dict[str, Any] = {}
    for label, path in paths.items():
        value = dotted_get(document, path, _MISSING)
        if value is _MISSING:
            continue
        encoded = json.dumps(value, allow_nan=False)
        if len(encoded.encode("utf-8")) > 256 * 1024:
            continue
        result[label] = json.loads(encoded)
    return result


def _source_state(document: dict, spec: dict) -> str:
    explicit = dotted_get(document, spec.get("state_path"), _MISSING)
    if explicit is not _MISSING:
        source_state = str(explicit).lower()
        return (spec.get("state_map") or {}).get(source_state, source_state)
    healthy = dotted_get(document, spec.get("healthy_path"), _MISSING)
    if healthy is True:
        return "healthy"
    if healthy is False:
        return "degraded"
    return "unknown"


def _nonnegative_int(document: dict, path: str | None) -> int | None:
    value = dotted_get(document, path, _MISSING)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _source_kind(connector: str) -> str:
    return {
        "json_file": "sanitized_snapshot",
        "http_json": "read_only_api",
        "static": "catalog",
    }.get(connector, "unknown")


def _add_contract_metadata(result: dict, spec: dict, document: dict) -> dict:
    result["provenance"] = {
        "source_system": spec["id"],
        "source_kind": _source_kind(spec["connector"]),
        "source_owner": spec.get("source_owner"),
        "collection_cadence_seconds": spec.get("collection_cadence_seconds"),
    }
    result["connector_health"] = {
        "state": result["state"],
        "freshness": result["freshness"],
        "last_success_at": result.get("collected_at") if result.get("state") in {"healthy", "degraded", "stale"} else None,
        "collection_duration_ms": _nonnegative_int(document, spec.get("collection_duration_ms_path")),
        "record_count": _nonnegative_int(document, spec.get("record_count_path")),
        "reason_code": result.get("reason_code"),
    }
    # Publication is fail-closed until a provider implements and tests bounded
    # record validators for the versioned entity and relationship contract.
    result["entities"] = []
    result["relationships"] = []
    return result


def _result(spec: dict, document: dict, now: datetime | None) -> dict:
    result = classify_snapshot(
        integration_id=spec["id"],
        name=spec["name"],
        category=spec.get("category"),
        collected_at=dotted_get(document, spec.get("collected_at_path")),
        max_age_seconds=spec["max_age_seconds"],
        source_state=_source_state(document, spec),
        summary=_summary(document, spec.get("summary_paths") or {}),
        deep_link=spec.get("deep_link"),
        now=now,
    )
    return _add_contract_metadata(result, spec, document)


def _error(spec: dict, state: str, reason_code: str, now: datetime | None) -> dict:
    result = classify_snapshot(
        integration_id=spec["id"],
        name=spec["name"],
        category=spec.get("category"),
        collected_at=None,
        max_age_seconds=spec["max_age_seconds"],
        source_state=state,
        summary={},
        deep_link=spec.get("deep_link"),
        now=now,
        reason_code=reason_code,
        detail="The source could not be collected. Review server-side portal logs.",
    )
    return _add_contract_metadata(result, spec, {})


def collect_integration(spec: dict, now: datetime | None = None) -> dict:
    connector = spec["connector"]
    if connector == "static":
        document = {
            "state": spec.get("state", "unknown"),
            "collected_at": spec.get("collected_at"),
            "summary": spec.get("summary", {}),
        }
        normalized = dict(spec)
        normalized.setdefault("state_path", "state")
        normalized.setdefault("collected_at_path", "collected_at")
        normalized.setdefault("summary_paths", {key: f"summary.{key}" for key in document["summary"]})
        return _result(normalized, document, now)
    if connector == "json_file":
        try:
            path = Path(spec["path"])
            if path.is_symlink() or path.stat().st_size > 1024 * 1024:
                raise ValueError('snapshot path rejected')
            document = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("source is not an object")
            return _result(spec, document, now)
        except (OSError, ValueError, json.JSONDecodeError):
            return _error(spec, "unavailable", "source_unavailable", now)
    if connector == "http_json":
        headers = {"Accept": "application/json", "User-Agent": "Cerebro-Public/1.0"}
        request = urllib.request.Request(spec["url"], headers=headers, method="GET")
        context = ssl.create_default_context(cafile=spec.get("ca_file"))
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            NoRedirect(),
        )
        try:
            with opener.open(request, timeout=10) as response:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError('feed too large')
                document = json.loads(raw)
            if not isinstance(document, dict):
                raise ValueError("source is not an object")
            return _result(spec, document, now)
        except urllib.error.HTTPError as exc:
            if exc.code in {301, 302, 303, 307, 308}:
                return _error(spec, "unavailable", "source_redirect_refused", now)
            if exc.code in {401, 403}:
                return _error(spec, "unauthorized", "source_unauthorized", now)
            return _error(spec, "unavailable", "source_http_error", now)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
            return _error(spec, "unavailable", "source_unavailable", now)
    return _error(spec, "unknown", "connector_unsupported", now)
