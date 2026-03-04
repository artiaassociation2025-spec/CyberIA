import os
import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # CyberIA/
RAW_DIR = BASE_DIR / "data" / "raw"
OUTPUT_FILE = BASE_DIR / "data" / "staged" / "cve_list.json"
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves_from_file(path: Path) -> set:
    try:
        blob = path.read_text(encoding="utf-8")
        return set(c.upper() for c in CVE_REGEX.findall(blob))
    except Exception:
        return set()


def main() -> list:
    all_cves = set()

    for root, _, files in os.walk(RAW_DIR):
        for file in files:
            if not file.endswith(".json"):
                continue
            path = Path(root) / file
            all_cves |= extract_cves_from_file(path)

    cve_list = sorted(all_cves)
    OUTPUT_FILE.write_text(
        json.dumps(cve_list, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"[extract_cves] Found {len(cve_list)} unique CVEs -> {OUTPUT_FILE}")
    return cve_list


if __name__ == "__main__":
    main()