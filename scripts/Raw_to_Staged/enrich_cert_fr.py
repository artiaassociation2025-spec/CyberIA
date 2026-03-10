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
# Parse a CERT-FR advisory into the UNIFIED advisory structure
# --------------------------------------------------------

def parse_advisory(data: dict, path: Path) -> dict:
    revisions = data.get("revisions") or []
    published = revisions[0].get("revision_date", "")[:10] if revisions else None

    cves = [c.get("name", "").upper() for c in (data.get("cves") or []) if c.get("name")]

    return {
        # ── Identity ──
        "id":               f"advisory--{data.get('reference', path.stem)}",
        "source":           "cert-fr",
        "publisher":        "CERT-FR",
        "advisory_id":      data.get("reference"),
        "title":            data.get("title"),
        "date":             published,

        # ── Text ──
        "description":      data.get("summary"),
        "content":          data.get("content"),
        "related_cves":     cves,
        "risks":            [r.get("description") for r in (data.get("risks") or [])],

        # ── Technical (CERT-FR doesn't provide these per-advisory) ──
        "cwe":              [],
        "cvss": {
            "version":      None,
            "score":        None,
            "vector":       None,
            "severity":     None
        },
        "remediations":     [],

        # ── Products & References ──
        "affected_products": [
            {
                "product":   s.get("product", {}).get("name"),
                "vendor":    s.get("product", {}).get("vendor", {}).get("name"),
                "versions":  [],
                "status":    "affected",
                "description": s.get("description")
            }
            for s in (data.get("affected_systems") or [])
        ],
        "references":       [
            v.get("url")
            for v in (data.get("vendor_advisories") or [])
            if v.get("url")
        ],
        "revisions":        [
            {
                "date":        r.get("revision_date", "")[:10],
                "description": r.get("description")
            }
            for r in revisions
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

                # Access the new advisories structure
                adv_block = skel["entities"]["advisories"]
                adv_list = adv_block.setdefault("list", [])

                # Get latest revision date from incoming advisory
                new_date = advisory.get("date") or ""

                existing_idx = next((i for i, a in enumerate(adv_list) if a.get("id") == advisory["id"]), None)

                if existing_idx is not None:
                    old_date = adv_list[existing_idx].get("date") or ""
                    if new_date <= old_date:
                        continue  # nothing changed, skip
                    adv_list[existing_idx] = advisory  # newer version, overwrite
                else:
                    adv_list.append(advisory)  # new advisory, add it

                # Set source flag to 1
                adv_block.setdefault("sources", {})["cert-fr"] = 1

                # Track source in cve object too
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
