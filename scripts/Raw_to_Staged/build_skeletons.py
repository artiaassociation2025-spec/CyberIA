import json
from pathlib import Path
from datetime import datetime, UTC

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # CyberIA/
CVE_LIST_FILE = BASE_DIR / "data" / "staged" / "cve_list.json"
OUTPUT_DIR = BASE_DIR / "data" / "staged" / "cves"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def now_utc():
    return datetime.now(UTC).date().isoformat()


# --------------------------------------------------------
# Unified advisory template — same structure for ALL sources
# Used by: enrich_cert_fr, enrich_cert_bund, enrich_cert_eu
# Fields a source doesn't have stay null / []
# --------------------------------------------------------

def empty_advisory():
    """Return a blank unified advisory entry."""
    return {
        "id":               None,
        "source":           None,
        "publisher":        None,
        "advisory_id":      None,
        "title":            None,
        "date":             None,
        "description":      None,
        "content":          None,
        "related_cves":     [],
        "risks":            [],
        "cwe":              [],
        "cvss": {
            "version":      None,
            "score":        None,
            "vector":       None,
            "severity":     None
        },
        "remediations":     [],
        "affected_products": [],
        "references":       [],
        "revisions":        []
    }


def make_skeleton(cve_id: str) -> dict:
    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),

        "sources": [],

        "entities": {
            "tactics": [],
            "techniques": [],
            "groups": [],
            "software": [],
            "products": [],

            "cve": {
                "id": f"vuln--{cve_id}",
                "cve": cve_id,
                "description": None,
                "cwe": [],
                "cvss": {
                    "version": None,
                    "score": None,
                    "vector": None,
                    "severity": None
                },
                "affected_products": [],
                "exploitation": {
                    "known_exploited": None,
                    "in_cisa_kev": None,
                    "ransomware": None,
                    "public_exploit": None
                },
                "dates": {
                    "published": None,
                    "last_modified": None,
                    "kev_added": None,
                    "patch_due": None
                },
                "epss": {
                    "score": None,
                    "percentile": None,
                    "date": None
                },
                "references": [],
                "sources": []
            },

            "advisories": {
                "sources": {
                    "cert-fr": 0,
                    "cert-bund": 0,
                    "cert-eu": 0
                },
                "list": [
                    # Each entry follows this unified structure (shown as template):
                    # {
                    #     "id":               "advisory--CERTFR-2026-AVI-0228",
                    #     "source":           "cert-fr" | "cert-bund" | "cert-eu",
                    #     "publisher":        "CERT-FR" | "BSI" | "CERT-EU",
                    #     "advisory_id":      "CERTFR-2026-AVI-0228",
                    #     "title":            "...",
                    #     "date":             "2026-02-02",
                    #     "description":      "short summary",
                    #     "content":          "full remediation / markdown text",
                    #     "related_cves":     ["CVE-2026-23220", "CVE-2026-23222"],
                    #     "risks":            ["Exécution de code", "Déni de service"],
                    #     "cwe":              ["CWE-79", "CWE-346"],
                    #     "cvss":             {"version": "3.1", "score": 9.8, "vector": "...", "severity": "critical"},
                    #     "remediations":     [{"type": "vendor_fix", "description": "...", "url": "..."}],
                    #     "affected_products": [{"product": "...", "vendor": "...", "versions": [], "status": "..."}],
                    #     "references":       ["https://..."],
                    #     "revisions":        [{"date": "2026-02-02", "description": "..."}]
                    # }
                ]
            },

            "enisa_threats": [],
            "nis2_sectors": [],
            "controls": [],
            "indicators": []
        },

        "relationships": []
    }


def main(cve_list: list = None):
    # Load CVE list from file if not passed directly
    if cve_list is None:
        if not CVE_LIST_FILE.exists():
            print("[build_skeletons] ERROR: cve_list.json not found. Run extract_cves.py first.")
            return
        cve_list = json.loads(CVE_LIST_FILE.read_text(encoding="utf-8"))

    created = 0
    skipped = 0

    for cve_id in cve_list:
        out_path = OUTPUT_DIR / f"{cve_id}.json"

        # Don't overwrite existing skeletons (they may already be enriched)
        if out_path.exists():
            skipped += 1
            continue

        skeleton = make_skeleton(cve_id)
        out_path.write_text(
            json.dumps(skeleton, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        created += 1

    print(f"[build_skeletons] Created: {created} | Skipped (already exist): {skipped}")


if __name__ == "__main__":
    main()
