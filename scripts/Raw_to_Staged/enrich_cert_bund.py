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
# Parse RICH advisory (bsi / bsi-cvd)
# --------------------------------------------------------

def parse_rich_vulnerability(vuln: dict, advisory_id: str, advisory_date: str) -> list:
    """
    Extract per-CVE details from a full CSAF vulnerability entry.
    Returns list of dicts (one per CVE, though typically just one).
    """
    entries = []
    
    cve_id = vuln.get("cve")
    if not cve_id:
        return entries
    
    cve_id = cve_id.upper()
    
    # Extract description
    description = None
    for note in (vuln.get("notes") or []):
        if note.get("category") in ("summary", "description"):
            description = note.get("text")
            if description:
                break
    
    # Extract CWE
    cwes = []
    cwe_obj = vuln.get("cwe", {})
    if isinstance(cwe_obj, dict) and cwe_obj.get("id"):
        cwes.append(cwe_obj["id"])
    
    # Extract CVSS scores
    cvss_block = {"version": None, "score": None, "vector": None, "severity": None}
    for score_entry in (vuln.get("scores") or []):
        cvss_v3 = score_entry.get("cvss_v3", {})
        if cvss_v3:
            cvss_block = {
                "version":  cvss_v3.get("version"),
                "score":    cvss_v3.get("baseScore"),
                "vector":   cvss_v3.get("vectorString"),
                "severity": cvss_v3.get("baseSeverity", "").lower() or None
            }
            break
    
    # Extract remediations
    remediations = []
    for rem in (vuln.get("remediations") or []):
        remediations.append({
            "category": rem.get("category"),
            "details":  rem.get("details"),
            "url":      rem.get("url")
        })
    
    # Extract affected products (from product_status)
    affected_products = []
    product_status = vuln.get("product_status", {})
    
    for status, product_ids in product_status.items():
        for pid in (product_ids or []):
            affected_products.append({
                "product_id": pid,
                "status":     status  # known_affected, fixed, known_not_affected, etc.
            })
    
    entries.append({
        "cve_id":          cve_id,
        "description":     description,
        "cwe":             cwes,
        "cvss":            cvss_block,
        "remediations":    remediations,
        "affected_products": affected_products,
        "title":           vuln.get("title")
    })
    
    return entries


def parse_rich_advisory(data: dict, path: Path) -> dict:
    """Parse a full CSAF security advisory (bsi or bsi-cvd)."""
    doc = data.get("document", {})
    tracking = doc.get("tracking", {})
    
    advisory_id = tracking.get("id")
    initial_date = tracking.get("initial_release_date", "")[:10] if tracking.get("initial_release_date") else None
    current_date = tracking.get("current_release_date", "")[:10] if tracking.get("current_release_date") else None
    advisory_date = current_date or initial_date
    
    # Parse all vulnerabilities
    cve_entries = []
    for vuln in (data.get("vulnerabilities") or []):
        cve_entries.extend(parse_rich_vulnerability(vuln, advisory_id, advisory_date))
    
    return {
        "source":        "cert-bund",
        "type":          "security_advisory",
        "advisory_id":   advisory_id,
        "title":         doc.get("title"),
        "date":          advisory_date,
        "publisher":     doc.get("publisher", {}).get("name", "BSI"),
        "summary":       None,  # Extract from notes if needed
        "cves":          cve_entries,
        "references":    [ref.get("url") for ref in (doc.get("references") or []) if ref.get("url")]
    }


# --------------------------------------------------------
# Parse MINIMAL advisory (bsi-wid)
# --------------------------------------------------------

def parse_minimal_vulnerability(vuln: dict, advisory_id: str, advisory_date: str) -> list:
    """
    Extract minimal per-CVE details from a base CSAF vulnerability entry.
    """
    entries = []
    
    cve_id = vuln.get("cve")
    if not cve_id:
        return entries
    
    cve_id = cve_id.upper()
    release_date = vuln.get("release_date", "")[:10] if vuln.get("release_date") else advisory_date
    
    # Only product status available in wid format
    affected_products = []
    product_status = vuln.get("product_status", {})
    
    for status, product_ids in product_status.items():
        for pid in (product_ids or []):
            affected_products.append({
                "product_id": pid,
                "status":     status
            })
    
    entries.append({
        "cve_id":          cve_id,
        "release_date":    release_date,
        "title":           vuln.get("title"),
        "affected_products": affected_products
    })
    
    return entries


def parse_minimal_advisory(data: dict, path: Path) -> dict:
    """Parse a minimal CSAF base advisory (bsi-wid)."""
    doc = data.get("document", {})
    tracking = doc.get("tracking", {})
    
    advisory_id = tracking.get("id")
    initial_date = tracking.get("initial_release_date", "")[:10] if tracking.get("initial_release_date") else None
    current_date = tracking.get("current_release_date", "")[:10] if tracking.get("current_release_date") else None
    advisory_date = current_date or initial_date
    
    # Parse all vulnerabilities
    cve_entries = []
    for vuln in (data.get("vulnerabilities") or []):
        cve_entries.extend(parse_minimal_vulnerability(vuln, advisory_id, advisory_date))
    
    return {
        "source":       "cert-bund",
        "type":         "base",
        "advisory_id":  advisory_id,
        "title":        doc.get("title"),
        "date":         advisory_date,
        "publisher":    doc.get("publisher", {}).get("name", "BSI"),
        "cves":         cve_entries,
        "references":   [ref.get("url") for ref in (doc.get("references") or []) if ref.get("url")]
    }


# --------------------------------------------------------
# Build advisory entry for skeleton
# --------------------------------------------------------

def build_advisory_entry(advisory: dict, cve_id: str) -> dict:
    """
    Build an advisory entry to append to a CVE skeleton.
    cve_id is the specific CVE being enriched.
    """
    # Find the CVE entry for this specific CVE ID
    cve_data = None
    for cve in advisory.get("cves", []):
        if cve["cve_id"] == cve_id:
            cve_data = cve
            break
    
    if not cve_data:
        return None
    
    entry = {
        "id":          f"advisory--{advisory['advisory_id']}",
        "source":      "cert-bund",
        "publisher":   advisory.get("publisher"),
        "advisory_id": advisory.get("advisory_id"),
        "title":       advisory.get("title"),
        "date":        advisory.get("date"),
        "advisory_type": advisory.get("type"),
        "cve_in_advisory": cve_id
    }
    
    # Add type-specific fields
    if advisory.get("type") == "security_advisory":
        # Rich advisory has detailed per-CVE info
        entry.update({
            "description":     cve_data.get("description"),
            "cwe":             cve_data.get("cwe", []),
            "cvss":            cve_data.get("cvss"),
            "remediations":    cve_data.get("remediations", []),
            "affected_products": cve_data.get("affected_products", []),
        })
    else:
        # Minimal advisory only has product status
        entry.update({
            "affected_products": cve_data.get("affected_products", []),
        })
    
    entry["references"] = advisory.get("references", [])
    
    return entry


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
                    advisory = parse_rich_advisory(data, path)
                elif category == "base":
                    advisory = parse_minimal_advisory(data, path)
                else:
                    continue
                
                if not advisory.get("cves"):
                    continue
                
                total_files += 1
                
                # For each CVE in this advisory, update the corresponding skeleton
                for cve_data in advisory.get("cves", []):
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
                    advisories = skel["entities"].setdefault("advisories", [])
                    
                    # Build the advisory entry
                    advisory_entry = build_advisory_entry(advisory, cve_id)
                    if not advisory_entry:
                        continue
                    
                    # Check for existing entry and update if newer
                    new_date = advisory_entry.get("date") or ""
                    existing_idx = next(
                        (i for i, a in enumerate(advisories) if a.get("id") == advisory_entry["id"]),
                        None
                    )
                    
                    if existing_idx is not None:
                        old_date = advisories[existing_idx].get("date") or ""
                        if new_date <= old_date:
                            continue  # No update needed
                        advisories[existing_idx] = advisory_entry  # Overwrite with newer
                    else:
                        advisories.append(advisory_entry)  # New advisory
                    
                    # Track source
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