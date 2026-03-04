import os
import json
from pathlib import Path
from datetime import datetime, UTC

BASE_DIR    = Path(__file__).resolve().parent.parent.parent  # CyberIA/
RAW_DIR     = BASE_DIR / "data" / "raw" / "certfr"
CVE_DIR     = BASE_DIR / "data" / "staged" / "cves"


def now_utc():
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


# --------------------------------------------------------
# Parse a CERT-FR advisory into a clean advisory entry
# --------------------------------------------------------

def parse_advisory(data: dict, path: Path) -> dict:
    revisions = data.get("revisions") or []
    published = revisions[0].get("revision_date", "")[:10] if revisions else None

    cves = [c.get("name", "").upper() for c in (data.get("cves") or []) if c.get("name")]

    return {
        "id":          f"advisory--{data.get('reference', path.stem)}",
        "source":      "cert-fr",
        "publisher":   "CERT-FR",
        "reference":   data.get("reference"),
        "title":       data.get("title"),
        "summary":     data.get("summary"),
        "content":     data.get("content"),
        "date":        published,
        "related_cves": cves,
        "revisions":   [
            {
                "date":        r.get("revision_date", "")[:10],
                "description": r.get("description")
            }
            for r in revisions
        ],
        "risks": [r.get("description") for r in (data.get("risks") or [])],
        "affected_systems": [
            {
                "description": s.get("description"),
                "product":     s.get("product", {}).get("name"),
                "vendor":      s.get("product", {}).get("vendor", {}).get("name")
            }
            for s in (data.get("affected_systems") or [])
        ],
        "vendor_advisories": [
            {
                "title":        v.get("title"),
                "url":          v.get("url"),
                "published_at": v.get("published_at")
            }
            for v in (data.get("vendor_advisories") or [])
        ]
    }


# --------------------------------------------------------
# MAIN
# --------------------------------------------------------

def main():
    total_files     = 0
    total_enriched  = 0
    total_skipped   = 0

    for root, _, files in os.walk(RAW_DIR):
        for file in files:
            if not file.endswith(".json"):
                continue

            path = Path(root) / file
            data = load_json(path)
            if not isinstance(data, dict):
                continue

            # Get all CVEs mentioned in this advisory
            cve_refs = [
                c.get("name", "").upper()
                for c in (data.get("cves") or [])
                if c.get("name")
            ]
            if not cve_refs:
                continue

            total_files += 1
            advisory = parse_advisory(data, path)

            for cve_id in cve_refs:
                skel_path = CVE_DIR / f"{cve_id}.json"

                # Skip silently if no skeleton exists
                if not skel_path.exists():
                    total_skipped += 1
                    continue

                skel = json.loads(skel_path.read_text(encoding="utf-8"))
                advisories = skel["entities"].setdefault("advisories", [])

                # Get latest revision date from incoming advisory
                new_date = advisory.get("date") or ""

                existing_idx = next((i for i, a in enumerate(advisories) if a.get("id") == advisory["id"]), None)

                if existing_idx is not None:
                    old_date = advisories[existing_idx].get("date") or ""
                    if new_date <= old_date:
                        continue  # nothing changed, skip
                    advisories[existing_idx] = advisory  # newer version, overwrite
                else:
                    advisories.append(advisory)  # new advisory, add it

                # Track source
                cve_obj = skel["entities"]["cve"]
                if "cert-fr" not in cve_obj.get("sources", []):
                    cve_obj.setdefault("sources", []).append("cert-fr")

                skel["generated_at"] = now_utc()
                skel_path.write_text(
                    json.dumps(skel, indent=2, ensure_ascii=False),
                    encoding="utf-8"
                )
                total_enriched += 1

    print(f"[enrich_cert_fr] Files processed: {total_files} | Skeletons enriched: {total_enriched} | Skipped (no skeleton): {total_skipped}")


if __name__ == "__main__":
    main()