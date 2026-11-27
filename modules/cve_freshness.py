"""Offline metadata inspection for VaktScan vulnerability data sources."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


DEFAULT_DATABASES = (
    ("nvd", "nvd_cve_db.json", 14),
    ("retirejs", "retirejs_db.json", 30),
    ("bundled_components", "bundled_cves.json", 30),
    ("cisa_kev", "cisa_kev_cache.json", 7),
)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _coverage_counts(data: Dict[str, Any]) -> Dict[str, int]:
    meta = data.get("_meta") if isinstance(data.get("_meta"), dict) else {}
    index = data.get("index") if isinstance(data.get("index"), dict) else {}
    components = data.get("components") if isinstance(data.get("components"), dict) else {}
    vulnerabilities = data.get("vulnerabilities") if isinstance(data.get("vulnerabilities"), list) else []
    products = meta.get("products") if isinstance(meta.get("products"), dict) else {}
    if not components and not index and not vulnerabilities and not products:
        # RetireJS data is a top-level library mapping.
        libraries = [key for key, value in data.items() if not key.startswith("_") and isinstance(value, dict)]
        advisories = sum(len(data[key].get("vulnerabilities", [])) for key in libraries)
        return {"products": 0, "components": 0, "libraries": len(libraries), "advisories": advisories}
    advisories = (
        sum(len(rows) if isinstance(rows, list) else 1 for rows in index.values()) + len(vulnerabilities) +
        sum(len(rows) for rows in components.values() if isinstance(rows, list))
    )
    return {
        "products": len(products),
        "components": len(components),
        "libraries": 0,
        "advisories": advisories,
    }


def _retirejs_refresh_metadata(path: Path) -> Dict[str, Any]:
    """Trust a successful RetireJS check only for the exact downloaded database."""
    sidecar = path.with_suffix(".meta.json")
    try:
        metadata = json.loads(sidecar.read_text(encoding="utf-8"))
        if metadata.get("sha256") == hashlib.sha256(path.read_bytes()).hexdigest():
            return metadata
    except (OSError, ValueError, AttributeError):
        pass
    return {}


def inspect_database(path: str | Path, *, name: str | None = None, now: datetime | None = None,
                     stale_after_days: int = 30) -> Dict[str, Any]:
    path = Path(path)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    result = {
        "name": name or path.stem,
        "path": str(path),
        "exists": path.is_file(),
        "status": "missing",
        "stale_after_days": int(stale_after_days),
        "refreshed_at": None,
        "freshness_basis": None,
        "age_days": None,
        "source": None,
        "schema_version": None,
        "minimum_cvss": None,
        "coverage": {"products": 0, "components": 0, "libraries": 0, "advisories": 0},
        "warning": None,
    }
    if not path.is_file():
        result["warning"] = "Vulnerability data source is missing."
        return result
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        result.update({"status": "invalid", "warning": f"Unable to read vulnerability data: {exc}"})
        return result
    if not isinstance(data, dict):
        result.update({"status": "invalid", "warning": "Vulnerability data root is not an object."})
        return result

    meta = data.get("_meta") if isinstance(data.get("_meta"), dict) else {}
    if (name or path.stem) == "retirejs" and not meta.get("refreshed_at"):
        meta = _retirejs_refresh_metadata(path)
    refreshed = _parse_time(meta.get("refreshed_at") or data.get("dateReleased") or data.get("updated_at"))
    result.update({
        "source": meta.get("source") or data.get("title"),
        "schema_version": meta.get("schema_version"),
        "minimum_cvss": meta.get("min_cvss"),
        "coverage": _coverage_counts(data),
    })
    if refreshed is None:
        result.update({
            "status": "unknown",
            "warning": "No authoritative refresh timestamp is embedded; file modification time is not treated as feed freshness.",
        })
        return result
    age_days = max(0.0, (now - refreshed).total_seconds() / 86400)
    stale = age_days > stale_after_days
    result.update({
        "refreshed_at": refreshed.isoformat().replace("+00:00", "Z"),
        "freshness_basis": "verified_sidecar" if (name or path.stem) == "retirejs" and meta.get("sha256") else "embedded_metadata",
        "age_days": round(age_days, 2),
        "status": "stale" if stale else "fresh",
        "warning": f"Vulnerability data is {age_days:.1f} days old (limit {stale_after_days} days)." if stale else None,
    })
    return result


def inspect_default_databases(data_dir: str | Path | None = None, *, now: datetime | None = None,
                              max_age_days: int | None = None) -> List[Dict[str, Any]]:
    root = Path(data_dir) if data_dir else Path(__file__).resolve().parent / "data"
    return [
        inspect_database(root / filename, name=name, now=now,
                         stale_after_days=max_age_days if max_age_days is not None else threshold)
        for name, filename, threshold in DEFAULT_DATABASES
    ]


def freshness_warnings(records: Iterable[Dict[str, Any]]) -> List[str]:
    return [f"{row.get('name', 'database')}: {row['warning']}" for row in records if row.get("warning")]
