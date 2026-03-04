import csv
import gzip
import json
import io
import urllib.request
from pathlib import Path
from datetime import datetime, UTC

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # CyberIA/
CVE_DIR  = BASE_DIR / "data" / "staged" / "cves"

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def now_utc():
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def download_epss() -> dict:
    """Download and parse EPSS CSV, return dict {cve_id: {score, percentile, date}}."""
    print("[enrich_epss] Downloading EPSS data...")
    with urllib.request.urlopen(EPSS_URL) as resp:
        compressed = resp.read()

    with gzip.open(io.BytesIO(compressed), "rt", encoding="utf-8") as f:
        # First line is a comment like: #model_version:v2026.03.01,score_date:2026-03-03T00:00:00+0000
        comment = f.readline().strip().lstrip("#")
        meta = dict(kv.split(":", 1) for kv in comment.split(",") if ":" in kv)
        score_date = meta.get("score_date", now_utc())[:10]  # keep YYYY-MM-DD

        reader = csv.DictReader(f)  # headers: cve, epss, percentile
        epss_data = {}
        for row in reader:
            epss_data[row["cve"].upper()] = {
                "score":      round(float(row["epss"]), 6),
                "percentile": round(float(row["percentile"]), 6),
                "date":       score_date
            }

    print(f"[enrich_epss] Loaded {len(epss_data):,} EPSS entries (date: {score_date})")
    return epss_data


def enrich_skeletons(epss_data: dict):
    skeletons = list(CVE_DIR.glob("CVE-*.json"))
    if not skeletons:
        print("[enrich_epss] No skeletons found.")
        return

    enriched = 0
    not_found = 0

    for path in skeletons:
        cve_id = path.stem  # e.g. CVE-2024-12345

        if cve_id not in epss_data:
            not_found += 1
            continue

        data = json.loads(path.read_text(encoding="utf-8"))

        # Fill in the epss block already present in the skeleton
        epss = epss_data[cve_id]
        data["entities"]["cve"]["epss"]["score"]      = epss["score"]
        data["entities"]["cve"]["epss"]["percentile"] = epss["percentile"]
        data["entities"]["cve"]["epss"]["date"]       = epss["date"]
        data["generated_at"] = now_utc()

        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        enriched += 1

    print(f"[enrich_epss] Enriched: {enriched} | Not in EPSS dataset: {not_found}")


def main():
    epss_data = download_epss()
    enrich_skeletons(epss_data)


if __name__ == "__main__":
    main()