"""
generate_stats.py — Scans all CVE JSON files and produces stats.json for the dashboard.
Run after the main pipeline: python scripts/generate_stats.py
"""
import os
import json
from pathlib import Path
from datetime import datetime, UTC, timedelta
from collections import Counter, defaultdict

BASE_DIR = Path(__file__).resolve().parent.parent  # CyberIA/
CVE_DIR = BASE_DIR / "data" / "staged" / "cves"
STATS_FILE = BASE_DIR / "docs" / "stats.json"
HISTORY_FILE = BASE_DIR / "docs" / "stats_history.json"
STATS_FILE.parent.mkdir(parents=True, exist_ok=True)


def now_utc():
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def analyze_cves():
    """Scan all CVE files and compute statistics."""
    files = list(CVE_DIR.glob("CVE-*.json"))
    total = len(files)

    # Counters
    source_counter = Counter()  # cert-fr, cert-bund, nvd, epss
    advisory_sources = {"cert-fr": 0, "cert-bund": 0, "cert-eu": 0, "both_fr_bund": 0, "all_three": 0, "none": 0}
    cvss_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    epss_ranges = {"high_90": 0, "medium_50": 0, "low_10": 0, "minimal": 0, "none": 0}
    cwe_counter = Counter()
    product_counter = Counter()
    vendor_counter = Counter()
    year_counter = Counter()
    pub_timeline = Counter()  # publication year-month
    has_description = 0
    has_cvss = 0
    has_epss = 0
    has_references = 0

    for path in files:
        data = load_json(path)
        if not data:
            continue

        cve_obj = data.get("entities", {}).get("cve", {})
        adv_block = data.get("entities", {}).get("advisories", {})

        # ── Year from CVE ID ──
        cve_id = cve_obj.get("cve", path.stem)
        try:
            year = int(cve_id.split("-")[1])
            year_counter[year] += 1
        except (IndexError, ValueError):
            pass

        # ── Sources tracking ──
        cve_sources = cve_obj.get("sources", [])
        for s in cve_sources:
            source_counter[s] += 1

        # ── Advisory sources (0/1 flags) ──
        adv_sources = adv_block.get("sources", {}) if isinstance(adv_block, dict) else {}
        has_fr = adv_sources.get("cert-fr", 0) == 1
        has_bund = adv_sources.get("cert-bund", 0) == 1
        has_eu = adv_sources.get("cert-eu", 0) == 1

        if has_fr:
            advisory_sources["cert-fr"] += 1
        if has_bund:
            advisory_sources["cert-bund"] += 1
        if has_eu:
            advisory_sources["cert-eu"] += 1
        if has_fr and has_bund:
            advisory_sources["both_fr_bund"] += 1
        if has_fr and has_bund and has_eu:
            advisory_sources["all_three"] += 1
        if not has_fr and not has_bund and not has_eu:
            advisory_sources["none"] += 1

        # ── CVSS distribution ──
        cvss = cve_obj.get("cvss", {})
        score = cvss.get("score")
        severity = cvss.get("severity")
        if score is not None:
            has_cvss += 1
            if severity:
                sev = severity.lower()
                if sev in cvss_dist:
                    cvss_dist[sev] += 1
                elif score >= 9.0:
                    cvss_dist["critical"] += 1
                elif score >= 7.0:
                    cvss_dist["high"] += 1
                elif score >= 4.0:
                    cvss_dist["medium"] += 1
                else:
                    cvss_dist["low"] += 1
            else:
                if score >= 9.0:
                    cvss_dist["critical"] += 1
                elif score >= 7.0:
                    cvss_dist["high"] += 1
                elif score >= 4.0:
                    cvss_dist["medium"] += 1
                else:
                    cvss_dist["low"] += 1
        else:
            cvss_dist["none"] += 1

        # ── EPSS distribution ──
        epss = cve_obj.get("epss", {})
        epss_score = epss.get("score")
        if epss_score is not None:
            has_epss += 1
            pct = epss_score * 100
            if pct >= 90:
                epss_ranges["high_90"] += 1
            elif pct >= 50:
                epss_ranges["medium_50"] += 1
            elif pct >= 10:
                epss_ranges["low_10"] += 1
            else:
                epss_ranges["minimal"] += 1
        else:
            epss_ranges["none"] += 1

        # ── CWE ──
        for cwe in cve_obj.get("cwe", []):
            if cwe and cwe.startswith("CWE-"):
                cwe_counter[cwe] += 1

        # ── Affected products ──
        for prod in cve_obj.get("affected_products", []):
            cpe = prod.get("cpe", "")
            if cpe and ":" in cpe:
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    if vendor and vendor != "*":
                        vendor_counter[vendor] += 1
                    if product and product != "*":
                        product_counter[product] += 1

        # ── Description ──
        if cve_obj.get("description"):
            has_description += 1

        # ── References ──
        if cve_obj.get("references"):
            has_references += 1

        # ── Publication timeline ──
        pub_date = cve_obj.get("dates", {}).get("published")
        if pub_date and len(pub_date) >= 7:
            pub_timeline[pub_date[:7]] += 1  # YYYY-MM

    # ── Build output ──
    stats = {
        "generated_at": now_utc(),
        "total_cves": total,

        "enrichment": {
            "has_description": has_description,
            "has_cvss": has_cvss,
            "has_epss": has_epss,
            "has_references": has_references,
        },

        "sources": {
            "nvd": source_counter.get("nvd", 0),
            "epss": has_epss,
            "cert_fr": source_counter.get("cert-fr", 0),
            "cert_bund": source_counter.get("cert-bund", 0),
        },

        "advisory_coverage": advisory_sources,

        "cvss_distribution": cvss_dist,

        "epss_distribution": epss_ranges,

        "top_cwe": [
            {"id": cwe, "count": count}
            for cwe, count in cwe_counter.most_common(15)
        ],

        "top_products": [
            {"name": prod, "count": count}
            for prod, count in product_counter.most_common(15)
        ],

        "top_vendors": [
            {"name": vendor, "count": count}
            for vendor, count in vendor_counter.most_common(15)
        ],

        "cves_by_year": [
            {"year": year, "count": count}
            for year, count in sorted(year_counter.items())
        ],

        "publication_timeline": [
            {"month": month, "count": count}
            for month, count in sorted(pub_timeline.items())
        ][-24:],  # last 24 months
    }

    return stats


def update_history(stats):
    """Track daily stats for change detection (added/updated over time)."""
    history = []
    if HISTORY_FILE.exists():
        try:
            history = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            history = []

    today = datetime.now(UTC).strftime("%Y-%m-%d")

    # Remove today if already exists (re-run)
    history = [h for h in history if h.get("date") != today]

    history.append({
        "date": today,
        "total": stats["total_cves"],
        "has_cvss": stats["enrichment"]["has_cvss"],
        "has_epss": stats["enrichment"]["has_epss"],
        "cert_fr": stats["sources"]["cert_fr"],
        "cert_bund": stats["sources"]["cert_bund"],
    })

    # Keep last 90 days
    history = history[-90:]

    HISTORY_FILE.write_text(
        json.dumps(history, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    # Compute changes
    changes = {"daily": {}, "weekly": {}, "monthly": {}}

    if len(history) >= 2:
        prev = history[-2]
        changes["daily"] = {
            "added": stats["total_cves"] - prev.get("total", stats["total_cves"]),
            "date": prev.get("date", ""),
        }

    week_ago = [h for h in history if h["date"] <= (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%d")]
    if week_ago:
        prev = week_ago[-1]
        changes["weekly"] = {
            "added": stats["total_cves"] - prev.get("total", stats["total_cves"]),
            "since": prev.get("date", ""),
        }

    month_ago = [h for h in history if h["date"] <= (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%d")]
    if month_ago:
        prev = month_ago[-1]
        changes["monthly"] = {
            "added": stats["total_cves"] - prev.get("total", stats["total_cves"]),
            "since": prev.get("date", ""),
        }

    return changes, history


def main():
    print("[generate_stats] Scanning CVE files...")
    stats = analyze_cves()

    print(f"[generate_stats] Total CVEs: {stats['total_cves']:,}")
    print(f"[generate_stats] With CVSS: {stats['enrichment']['has_cvss']:,}")
    print(f"[generate_stats] With EPSS: {stats['enrichment']['has_epss']:,}")

    changes, history = update_history(stats)
    stats["changes"] = changes
    stats["history"] = history

    STATS_FILE.write_text(
        json.dumps(stats, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"[generate_stats] Stats saved to {STATS_FILE}")


if __name__ == "__main__":
    main()
