import json
import hashlib
import datetime
import requests
from pathlib import Path

BASE_URL = "https://cert.europa.eu"
ENDPOINT = "publications/security-advisories"

TIMEOUT = 20
HEADERS = {
    "User-Agent": "CERT-EU-Mirror/1.0 (+mokda project)",
    "Accept": "application/json",
}

MAX_CONSECUTIVE_MISSES = 50


def stable_hash(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def save_json(path: Path, obj: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def should_update(path: Path, new_obj: dict) -> bool:
    if not path.exists():
        return True

    try:
        old_obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return True

    return stable_hash(old_obj) != stable_hash(new_obj)


def fetch_json(session: requests.Session, url: str):
    r = session.get(url, headers=HEADERS, timeout=TIMEOUT)

    if r.status_code == 404:
        return None, 404
    if r.status_code != 200:
        return None, r.status_code

    content_type = r.headers.get("Content-Type", "").lower()
    if "application/json" not in content_type:
        return None, "not_json"

    try:
        return r.json(), 200
    except Exception:
        return None, "json_decode_error"


def download_year(base_dir: Path, year: int, session: requests.Session):
    print(f"\n===== YEAR {year} =====")

    year_dir = base_dir / str(year)
    year_dir.mkdir(parents=True, exist_ok=True)

    consecutive_misses = 0
    i = 1

    downloaded = 0
    updated = 0
    skipped = 0
    errors = 0

    while consecutive_misses < MAX_CONSECUTIVE_MISSES:
        ref = f"{year}-{i:03d}"
        url = f"{BASE_URL}/{ENDPOINT}/{ref}/json"
        out_file = year_dir / f"{ref}.json"

        obj, status = fetch_json(session, url)

        if status in (404, "not_json"):
            consecutive_misses += 1
            i += 1
            continue

        if status != 200:
            errors += 1
            print(f"[!] {ref} -> ERROR {status}")
            consecutive_misses = 0
            i += 1
            continue

        consecutive_misses = 0

        if should_update(out_file, obj):
            if out_file.exists():
                updated += 1
                print(f"[U] {ref}")
            else:
                downloaded += 1
                print(f"[+] {ref}")
            save_json(out_file, obj)
        else:
            skipped += 1
            print(f"[=] {ref} (no change)")

        i += 1

    print(
        f"\nDone {year} CERT-EU: "
        f"new={downloaded}, updated={updated}, skipped={skipped}, errors={errors}"
    )


def main():
    base_dir = Path("certeu_dump")
    current_year = datetime.datetime.now().year

    try:
        start_year = int(input("Enter start year (default 2010): ").strip() or "2010")
    except ValueError:
        print("Invalid year input. Using 2010.")
        start_year = 2010

    if start_year < 2000 or start_year > current_year:
        print(f"Start year must be between 2000 and {current_year}")
        return

    print(f"Dumping CERT-EU Security Advisories JSON from {start_year} to {current_year}")
    print(f"Output dir: {base_dir.resolve()}")

    with requests.Session() as session:
        for year in range(start_year, current_year + 1):
            download_year(base_dir, year, session)


if __name__ == "__main__":
    main()
