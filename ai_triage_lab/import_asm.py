"""Import stored observations only. Does not resolve URLs or scan targets."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from .contracts import canonical_hash, read_json, text


def import_scan(directory: Path) -> dict[str, Any]:
    meta = read_json(directory / "meta.json")
    rows = read_json(directory / "http.json")
    assets = read_json(directory / "assets.json")
    if not isinstance(meta, dict) or not isinstance(rows, list) or not isinstance(assets, list):
        raise ValueError("Expected metadata object and finding/asset arrays")
    if len(rows) > 5000 or len(assets) > 5000:
        raise ValueError("Too many findings/assets")
    text(meta.get("domain"), "domain", 253)
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("Asset must be an object")
        text(asset.get("host"), "host", 253)
        if not isinstance(asset.get("ips"), list) or any(not isinstance(ip, str) for ip in asset["ips"]):
            raise ValueError("Asset ips must be a string array")
    scan_id = canonical_hash({"meta": meta, "http": rows, "assets": assets})
    findings = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError("Finding must be an object")
        text(row.get("url"), "url", 8000)
        for key in ("final_url", "title", "server", "tls_not_after", "error"):
            if row.get(key) is not None:
                text(row[key], key, 200 if key == "title" else 8000, empty=True)
        status = row.get("status_code")
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise ValueError("Invalid HTTP status")
        score = row.get("risk_score")
        if score is not None and (type(score) not in (int, float) or not math.isfinite(score)):
            raise ValueError("Invalid heuristic score")
        findings.append({"id": f"asm-{index}-{canonical_hash(row)[:12]}",
                         "observed": row, "heuristic_score": score,
                         "provenance": {"source_scan": scan_id, "row": index,
                                        "trust": "untrusted-observation"}})
    return {"schema_version": 1, "scan_id": scan_id, "meta": meta, "assets": assets,
            "vantage": meta.get("vantage", "unknown"),
            "completeness": meta.get("completeness", "unknown"), "findings": findings}
