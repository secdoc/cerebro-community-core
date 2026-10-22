from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


VALID_STATES = {"healthy", "degraded", "stale", "unavailable", "unauthorized", "unknown", "planned"}

SCHEMA_VERSION = "cerebro.integration.v1"
ENTITY_TYPES = (
    "ip_address", "asset", "alert", "finding", "cve", "threat_model",
    "attack_technique", "atlas_technique", "source_system",
)
RELATIONSHIP_TYPES = (
    "affects", "associated_with", "detected_by", "maps_to", "observed_by", "supports",
)


def data_contract() -> dict[str, Any]:
    """Return the stable vocabulary implemented by this API version."""
    return {
        "entity_types": list(ENTITY_TYPES),
        "relationship_types": list(RELATIONSHIP_TYPES),
        "entity_required_fields": ["id", "type", "label", "provenance"],
        "relationship_required_fields": ["id", "type", "source_ref", "target_ref", "provenance"],
        "provenance_fields": [
            "source_system", "source_kind", "source_owner", "collection_cadence_seconds",
        ],
        "connector_health_fields": [
            "state", "freshness", "last_success_at", "collection_duration_ms",
            "record_count", "reason_code",
        ],
    }


def parse_timestamp(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def classify_snapshot(
    *,
    integration_id: str,
    name: str,
    collected_at: str | None,
    max_age_seconds: int,
    source_state: str,
    summary: dict[str, Any],
    deep_link: str | None,
    category: str | None = None,
    now: datetime | None = None,
    reason_code: str | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    parsed = parse_timestamp(collected_at)
    age_seconds = None if parsed is None else max(0, int((current - parsed).total_seconds()))
    freshness = "unknown" if age_seconds is None else ("fresh" if age_seconds <= max_age_seconds else "stale")
    state = source_state if source_state in VALID_STATES else "unknown"
    if state in {"healthy", "degraded"} and freshness == "stale":
        state = "stale"
    elif state == "healthy" and freshness == "unknown":
        state = "unknown"
    result: dict[str, Any] = {
        "id": integration_id,
        "name": name,
        "category": category or "other",
        "state": state,
        "freshness": freshness,
        "collected_at": parsed.isoformat().replace("+00:00", "Z") if parsed else None,
        "age_seconds": age_seconds,
        "max_age_seconds": max_age_seconds,
        "summary": summary,
        "deep_link": deep_link,
    }
    if reason_code:
        result["reason_code"] = reason_code
    if detail:
        result["detail"] = detail
    return result


def aggregate_overview(integrations: list[dict[str, Any]], generated_at: datetime | None = None) -> dict[str, Any]:
    current = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    counts = Counter(item.get("state", "unknown") for item in integrations)
    critical_alerts = sum(
        value
        for item in integrations
        for value in [item.get("summary", {}).get("critical_alerts", 0)]
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    )
    nonhealthy = sum(count for state, count in counts.items() if state not in {"healthy", "planned"})
    state = "healthy" if integrations and nonhealthy == 0 else "degraded"
    if not integrations:
        state = "unknown"
    return {
        "generated_at": current.isoformat().replace("+00:00", "Z"),
        "state": state,
        "integration_count": len(integrations),
        "nonhealthy_count": nonhealthy,
        "critical_alerts": critical_alerts,
        "counts": dict(sorted(counts.items())),
    }
