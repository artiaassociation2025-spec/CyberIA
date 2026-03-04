import json
import lzma
import urllib.request
from pathlib import Path
from datetime import datetime, UTC

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # CyberIA/
CVE_DIR  = BASE_DIR / "data" / "staged" / "cves"
TMP_DIR  = BASE_DIR / "data" / "staged" / "_tmp_nvd"

NVD_URL  = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"


def now_utc():
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------
# Detect which years are needed from existing skeletons
# --------------------------------------------------------

def get_needed_years() -> set:
    years = set()
    for path in CVE_DIR.glob("CVE-*.json"):
        try:
            year = int(path.stem.split("-")[1])
            years.add(year)
        except (IndexError, ValueError):
            continue
    return years


# --------------------------------------------------------
# Download + parse one yearly NVD file
# --------------------------------------------------------

def download_year(year: int) -> dict:
    """Download CVE-<year>.json.xz, decompress in memory, return dict keyed by CVE ID."""
    url = NVD_URL.format(year=year)
    print(f"[enrich_nvd] Downloading {url} ...")

    tmp_path = TMP_DIR / f"CVE-{year}.json.xz"
    TMP_DIR.mkdir(parents=True, exist_ok=True)

    try:
        urllib.request.urlretrieve(url, tmp_path)
        with lzma.open(tmp_path, "rt", encoding="utf-8") as f:
            raw = json.load(f)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    # Index by CVE ID
    index = {}
    for item in raw.get("cve_items", raw.get("CVE_Items", [])):
        cve_id = (
            item.get("id")
            or item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
        )
        if cve_id:
            index[cve_id.upper()] = item

    print(f"[enrich_nvd] Year {year}: {len(index):,} CVEs loaded")
    return index


# --------------------------------------------------------
# Extract fields from a raw NVD item
# --------------------------------------------------------

def parse_nvd_item(item: dict) -> dict:
    """Extract all relevant fields from a raw NVD item."""

    # ── Description ───────────────────────────────────────
    description = None
    desc_block = (
        item.get("descriptions")                                    # new NVD API format
        or item.get("cve", {}).get("description", {}).get("description_data", [])
    )
    for d in desc_block:
        if d.get("lang") in ("en", "eng"):
            description = d.get("value")
            break

    # ── CWE ───────────────────────────────────────────────
    cwes = []
    prob_type = (
        item.get("weaknesses")
        or item.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
    )
    for pt in prob_type:
        for desc in pt.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)

    # ── CVSS ──────────────────────────────────────────────
    cvss = {"version": None, "score": None, "vector": None, "severity": None}

    metrics = item.get("metrics", {})

    if metrics.get("cvssMetricV31"):
        m = metrics["cvssMetricV31"][0].get("cvssData", {})
        cvss = {
            "version":  "3.1",
            "score":    m.get("baseScore"),
            "vector":   m.get("vectorString"),
            "severity": m.get("baseSeverity", "").lower() or None
        }
    elif metrics.get("cvssMetricV30"):
        m = metrics["cvssMetricV30"][0].get("cvssData", {})
        cvss = {
            "version":  "3.0",
            "score":    m.get("baseScore"),
            "vector":   m.get("vectorString"),
            "severity": m.get("baseSeverity", "").lower() or None
        }
    elif metrics.get("cvssMetricV2"):
        m = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss = {
            "version":  "2.0",
            "score":    m.get("baseScore"),
            "vector":   m.get("vectorString"),
            "severity": metrics["cvssMetricV2"][0].get("baseSeverity", "").lower() or None
        }
    # Legacy format fallback
    else:
        impact = item.get("impact", {})
        for key, ver in [("baseMetricV3", "3.x"), ("baseMetricV2", "2.0")]:
            if key in impact:
                block = impact[key].get("cvssV3") or impact[key].get("cvssV2") or {}
                cvss = {
                    "version":  ver,
                    "score":    block.get("baseScore"),
                    "vector":   block.get("vectorString"),
                    "severity": block.get("baseSeverity", "").lower() or None
                }
                break

    # ── Affected products ─────────────────────────────────
    affected_products = []
    for config in item.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", node.get("cpe_match", [])):
                if not cpe_match.get("vulnerable", True):
                    continue
                cpe = cpe_match.get("criteria") or cpe_match.get("cpe23Uri")
                if not cpe:
                    continue
                entry = {"cpe": cpe, "versions": []}
                vi = cpe_match.get("versionStartIncluding")
                ve = cpe_match.get("versionEndExcluding")
                vei = cpe_match.get("versionEndIncluding")
                if vi:
                    entry["versions"].append(f">= {vi}")
                if ve:
                    entry["versions"].append(f"< {ve}")
                if vei:
                    entry["versions"].append(f"<= {vei}")
                affected_products.append(entry)

    # ── References ────────────────────────────────────────
    references = []
    for ref in (
        item.get("references", [])
        or item.get("cve", {}).get("references", {}).get("reference_data", [])
    ):
        url = ref.get("url")
        if url:
            references.append(url)

    # ── Dates ─────────────────────────────────────────────
    published    = item.get("published") or item.get("publishedDate")
    last_modified = item.get("lastModified") or item.get("lastModifiedDate")
    if published:
        published = published[:10]
    if last_modified:
        last_modified = last_modified[:10]

    return {
        "description":       description,
        "cwe":               list(set(cwes)),
        "cvss":              cvss,
        "affected_products": affected_products,
        "references":        references,
        "dates": {
            "published":     published,
            "last_modified": last_modified,
        }
    }


# --------------------------------------------------------
# Enrich skeletons for one year
# --------------------------------------------------------

def enrich_year(nvd_index: dict, year: int) -> tuple:
    skeletons = list(CVE_DIR.glob(f"CVE-{year}-*.json"))
    enriched = 0
    not_found = 0

    for path in skeletons:
        cve_id = path.stem

        if cve_id not in nvd_index:
            not_found += 1
            continue

        data     = json.loads(path.read_text(encoding="utf-8"))
        parsed   = parse_nvd_item(nvd_index[cve_id])
        cve_obj  = data["entities"]["cve"]

        # Overwrite all NVD fields
        cve_obj["description"]       = parsed["description"]
        cve_obj["cwe"]               = parsed["cwe"]
        cve_obj["cvss"]              = parsed["cvss"]
        cve_obj["affected_products"] = parsed["affected_products"]
        cve_obj["references"]        = parsed["references"]
        cve_obj["dates"]["published"]     = parsed["dates"]["published"]
        cve_obj["dates"]["last_modified"] = parsed["dates"]["last_modified"]

        # Track source
        if "nvd" not in cve_obj.get("sources", []):
            cve_obj.setdefault("sources", []).append("nvd")

        data["generated_at"] = now_utc()
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        enriched += 1

    return enriched, not_found


# --------------------------------------------------------
# MAIN
# --------------------------------------------------------

def main():
    years = get_needed_years()
    if not years:
        print("[enrich_nvd] No skeletons found.")
        return

    print(f"[enrich_nvd] Years to fetch: {sorted(years)}")

    total_enriched  = 0
    total_not_found = 0
    total_errors    = 0

    for year in sorted(years):
        try:
            nvd_index = download_year(year)
            enriched, not_found = enrich_year(nvd_index, year)
            total_enriched  += enriched
            total_not_found += not_found
            print(f"[enrich_nvd] Year {year} -> Enriched: {enriched} | Not in NVD: {not_found}")
        except Exception as e:
            print(f"[enrich_nvd] ERROR on year {year}: {e}")
            total_errors += 1

    # Cleanup tmp dir
    if TMP_DIR.exists():
        TMP_DIR.rmdir()

    print(f"\n[enrich_nvd] DONE — Enriched: {total_enriched} | Not found: {total_not_found} | Year errors: {total_errors}")


if __name__ == "__main__":
    main()