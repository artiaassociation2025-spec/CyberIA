import os
import json
from pathlib import Path
from datetime import datetime, UTC

BASE_DIR    = Path(__file__).resolve().parent.parent.parent  # CyberIA/
RAW_DIR     = BASE_DIR / "data" / "raw" / "certbund"
CVE_DIR     = BASE_DIR / "data" / "staged" / "cves"


def now_utc():
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


# --------------------------------------------------------
# Detect advisory type from category field
# --------------------------------------------------------

def detect_category(doc: dict) -> str:
    """Returns: 'security_advisory' (bsi/bsi-cvd) or 'base' (bsi-wid)"""
    category = doc.get("document", {}).get("category", "")
    if "security_advisory" in category:
        return "security_advisory"
    elif "base" in category:
        return "base"
    return "unknown"


# --------------------------------------------------------
# Extract per-CVE data from a RICH vulnerability entry
# --------------------------------------------------------

def extract_rich_cve(vuln: dict) -> dict:
    """Extract per-CVE details from a full CSAF vulnerability entry."""
    cve_id = vuln.get("cve")
    if not cve_id:
        return None

    cve_id = cve_id.upper()

    # Description
    description = None
    for note in (vuln.get("notes") or []):
        if note.get("category") in ("summary", "description"):
            description = note.get("text")
            if description:
                break

    # CWE
    cwes = []
    cwe_obj = vuln.get("cwe", {})
    if isinstance(cwe_obj, dict) and cwe_obj.get("id"):
        cwes.append(cwe_obj["id"])

    # CVSS
    cvss = {"version": None, "score": None, "vector": None, "severity": None}
    for score_entry in (vuln.get("scores") or []):
        cvss_v3 = score_entry.get("cvss_v3", {})
        if cvss_v3:
            cvss = {
                "version":  cvss_v3.get("version"),
                "score":    cvss_v3.get("baseScore"),
                "vector":   cvss_v3.get("vectorString"),
                "severity": cvss_v3.get("baseSeverity", "").lower() or None
            }
            break

    # Remediations
    remediations = []
    for rem in (vuln.get("remediations") or []):
        remediations.append({
            "type":        rem.get("category"),
            "description": rem.get("details"),
            "url":         rem.get("url")
        })

    # Affected products
    affected_products = []
    product_status = vuln.get("product_status", {})
    for status, product_ids in product_status.items():
        for pid in (product_ids or []):
            affected_products.append({
                "product":  pid,
                "vendor":   None,
                "versions": [],
                "status":   status
            })

    return {
        "cve_id":           cve_id,
        "description":      description,
        "cwe":              cwes,
        "cvss":             cvss,
        "remediations":     remediations,
        "affected_products": affected_products,
        "title":            vuln.get("title")
    }


# --------------------------------------------------------
# Extract per-CVE data from a MINIMAL vulnerability entry
# --------------------------------------------------------

def extract_minimal_cve(vuln: dict) -> dict:
    """Extract minimal per-CVE details from a base CSAF entry."""
    cve_id = vuln.get("cve")
    if not cve_id:
        return None

    cve_id = cve_id.upper()

    # Only product status available in wid format
    affected_products = []
    product_status = vuln.get("product_status", {})
    for status, product_ids in product_status.items():
        for pid in (product_ids or []):
            affected_products.append({
                "product":  pid,
                "vendor":   None,
                "versions": [],
                "status":   status
            })

    return {
        "cve_id":           cve_id,
        "description":      None,
        "cwe":              [],
        "cvss":             {"version": None, "score": None, "vector": None, "severity": None},
        "remediations":     [],
        "affected_products": affected_products,
        "title":            vuln.get("title")
    }


# --------------------------------------------------------
# Build UNIFIED advisory entry for a specific CVE
# --------------------------------------------------------

def build_unified_advisory(data: dict, cve_data: dict, category: str) -> dict:
    """
    Build a unified advisory entry from a CERT-Bund file.
    Same structure as CERT-FR and CERT-EU advisories.
    """
    doc = data.get("document", {})
    tracking = doc.get("tracking", {})

    advisory_id = tracking.get("id")
    initial_date = tracking.get("initial_release_date", "")[:10] if tracking.get("initial_release_date") else None
    current_date = tracking.get("current_release_date", "")[:10] if tracking.get("current_release_date") else None
    advisory_date = current_date or initial_date

    # Collect all CVE IDs from the file for related_cves
    all_cves = []
    for vuln in (data.get("vulnerabilities") or []):
        vid = vuln.get("cve")
        if vid:
            all_cves.append(vid.upper())

    # References
    references = [ref.get("url") for ref in (doc.get("references") or []) if ref.get("url")]

    # Revisions from tracking history
    revisions = []
    for rev in (tracking.get("revision_history") or []):
        revisions.append({
            "date":        rev.get("date", "")[:10] if rev.get("date") else None,
            "description": rev.get("summary") or rev.get("number")
        })

    # Aggregate severity as risk
    risks = []
    severity_text = doc.get("aggregate_severity", {}).get("text")
    if severity_text:
        risks.append(severity_text)

    return {
        # ── Identity ──
        "id":               f"advisory--{advisory_id}",
        "source":           "cert-bund",
        "publisher":        doc.get("publisher", {}).get("name", "BSI"),
        "advisory_id":      advisory_id,
        "title":            doc.get("title"),
        "date":             advisory_date,

        # ── Text ──
        "description":      cve_data.get("description"),
        "content":          None,
        "related_cves":     all_cves,
        "risks":            risks,

        # ── Technical ──
        "cwe":              cve_data.get("cwe", []),
        "cvss":             cve_data.get("cvss", {"version": None, "score": None, "vector": None, "severity": None}),
        "remediations":     cve_data.get("remediations", []),

        # ── Products & References ──
        "affected_products": cve_data.get("affected_products", []),
        "references":       references,
        "revisions":        revisions
    }


# --------------------------------------------------------
# MAIN
# --------------------------------------------------------

def main():
    total_files     = 0
    total_cves      = 0
    total_enriched  = 0
    total_skipped   = 0
    total_errors    = 0

    for root, _, files in os.walk(RAW_DIR):
        for file in files:
            if not file.endswith(".json"):
                continue

            path = Path(root) / file
            data = load_json(path)
            if not isinstance(data, dict):
                continue

            try:
                # Detect advisory type
                category = detect_category(data)

                if category == "security_advisory":
                    extractor = extract_rich_cve
                elif category == "base":
                    extractor = extract_minimal_cve
                else:
                    continue

                vulns = data.get("vulnerabilities") or []
                if not vulns:
                    continue

                # Extract per-CVE data
                cve_entries = []
                for vuln in vulns:
                    cve_data = extractor(vuln)
                    if cve_data:
                        cve_entries.append(cve_data)

                if not cve_entries:
                    continue

                total_files += 1

                # For each CVE, build a unified advisory and inject into skeleton
                for cve_data in cve_entries:
                    cve_id = cve_data.get("cve_id")
                    if not cve_id:
                        continue

                    total_cves += 1
                    skel_path = CVE_DIR / f"{cve_id}.json"

                    # Skip if no skeleton exists
                    if not skel_path.exists():
                        total_skipped += 1
                        continue

                    skel = json.loads(skel_path.read_text(encoding="utf-8"))

                    # Access the new advisories structure
                    adv_block = skel["entities"]["advisories"]
                    adv_list = adv_block.setdefault("list", [])

                    # Build unified advisory entry
                    advisory_entry = build_unified_advisory(data, cve_data, category)

                    # Check for existing entry and update if newer
                    new_date = advisory_entry.get("date") or ""
                    existing_idx = next(
                        (i for i, a in enumerate(adv_list) if a.get("id") == advisory_entry["id"]),
                        None
                    )

                    if existing_idx is not None:
                        old_date = adv_list[existing_idx].get("date") or ""
                        if new_date <= old_date:
                            continue  # No update needed
                        adv_list[existing_idx] = advisory_entry  # Overwrite with newer
                    else:
                        adv_list.append(advisory_entry)  # New advisory

                    # Set source flag to 1
                    adv_block.setdefault("sources", {})["cert-bund"] = 1

                    # Track source in cve object too
                    cve_obj = skel["entities"]["cve"]
                    if "cert-bund" not in cve_obj.get("sources", []):
                        cve_obj.setdefault("sources", []).append("cert-bund")

                    skel["generated_at"] = now_utc()
                    skel_path.write_text(
                        json.dumps(skel, indent=2, ensure_ascii=False),
                        encoding="utf-8"
                    )
                    total_enriched += 1

            except Exception as e:
                print(f"[enrich_cert_bund] ERROR processing {path}: {e}")
                total_errors += 1
                continue

    print(f"[enrich_cert_bund] Files processed: {total_files} | CVEs found: {total_cves} | Skeletons enriched: {total_enriched} | Skipped (no skeleton): {total_skipped} | Errors: {total_errors}")


if __name__ == "__main__":
    main()
