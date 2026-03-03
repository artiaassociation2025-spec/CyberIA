import os
import json
import re
from pathlib import Path
from datetime import datetime, UTC
from collections import defaultdict

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
OUTPUT_DIR = BASE_DIR / "data" / "staged" / "cves"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# --------------------------------------------------------
# Utilities
# --------------------------------------------------------

def now_utc():
    return datetime.now(UTC).date().isoformat()


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def extract_cves(data):
    blob = json.dumps(data, ensure_ascii=False)
    return sorted(set(c.upper() for c in CVE_REGEX.findall(blob)))


def detect_source(path: Path):
    parts = [p.lower() for p in path.parts]
    if "certfr" in parts:
        return "cert-fr"
    if "certbund" in parts:
        return "cert-bund"
    if "certeu" in parts or "cert-eu" in parts or "cert_eu" in parts:
        return "cert-eu"
    return None


# --------------------------------------------------------
# Structured Extractors
# --------------------------------------------------------

def extract_structured_entry(source, data, path):

    entry = {
        "advisory_file": str(path.relative_to(BASE_DIR)),
        "advisory_id": None,
        "title": None,
        "published": None,
        "description": None,
        "references": []
    }

    if source == "cert-fr":
        entry["advisory_id"] = data.get("reference")
        entry["title"] = data.get("title")
        entry["description"] = data.get("summary")
        revisions = data.get("revisions") or []
        if revisions:
            entry["published"] = revisions[0].get("revision_date")
        entry["references"] = [
            r.get("url")
            for r in (data.get("vendor_advisories") or [])
            if isinstance(r, dict) and r.get("url")
        ]

    elif source == "cert-bund":
        doc = data.get("document") or {}
        tracking = doc.get("tracking") or {}
        entry["advisory_id"] = tracking.get("id")
        entry["title"] = doc.get("title")
        entry["published"] = tracking.get("current_release_date")
        entry["references"] = [
            r.get("url")
            for r in (doc.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ]

    elif source == "cert-eu":
        entry["advisory_id"] = data.get("serial_number")
        entry["title"] = data.get("title")
        entry["published"] = data.get("publish_date")
        entry["description"] = data.get("description")
        entry["references"] = []

    return entry


# --------------------------------------------------------
# MAIN
# --------------------------------------------------------

def main():

    cve_index = {}

    for root, _, files in os.walk(RAW_DIR):
        for file in files:
            if not file.endswith(".json"):
                continue

            path = Path(root) / file
            source = detect_source(path)
            if not source:
                continue

            data = load_json(path)
            if not isinstance(data, dict):
                continue

            cves = extract_cves(data)
            if not cves:
                continue

            entry = extract_structured_entry(source, data, path)

            for cve_id in cves:

                if cve_id not in cve_index:
                    cve_index[cve_id] = {
                        "schema_version": "1.0",
                        "cve": cve_id,
                        "first_seen": None,
                        "last_updated": now_utc(),
                        "sources": defaultdict(list),
                    }

                if entry not in cve_index[cve_id]["sources"][source]:
                    cve_index[cve_id]["sources"][source].append(entry)

    # Write all CVEs
    for cve_id, data in cve_index.items():
        data["sources"] = dict(data["sources"])
        data["last_updated"] = now_utc()

        out_path = OUTPUT_DIR / f"{cve_id}.json"
        out_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

    print("Total unique CVEs:", len(cve_index))


if __name__ == "__main__":
    main()
