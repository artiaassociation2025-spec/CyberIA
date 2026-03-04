import traceback
from datetime import datetime, UTC

# ── Import all pipeline scripts here ──────────────────────────────────────────
import extract_cves
import build_skeletons
import enrich_epss
import enrich_nvd
import enrich_cert_fr
import enrich_cert_bund
# import enrich_cisa_kev  # (future)
# import enrich_cert_eu   # (future)
# ------------------------------------------------------------------------------

PIPELINE = [
    #("extract_cves",    extract_cves.main,    None),
    #("build_skeletons", build_skeletons.main, "cve_list"),
    #("enrich_epss",     enrich_epss.main,     None),
    #("enrich_nvd",      enrich_nvd.main,      None),
    #("enrich_cert_fr",  enrich_cert_fr.main,  None),
    ("enrich_cert_bund", enrich_cert_bund.main, None),
    # ("enrich_cisa_kev", enrich_cisa_kev.main, None),
    # ("enrich_cert_eu",  enrich_cert_eu.main,  None),
]


def run_pipeline():
    print(f"\n{'='*50}")
    print(f"  PIPELINE START — {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{'='*50}\n")

    errors = []
    context = {}  # shared data passed between steps

    for name, fn, input_key in PIPELINE:
        print(f"[run_all] >> Running: {name}")
        try:
            # Pass output from a previous step if requested
            arg = context.get(input_key) if input_key else None
            result = fn(arg) if arg is not None else fn()

            # Store result in context so next steps can use it
            context[name] = result

        except Exception as e:
            msg = f"[run_all] ERROR in {name}: {e}\n{traceback.format_exc()}"
            print(msg)
            errors.append({"step": name, "error": str(e)})

        print()

    print(f"{'='*50}")
    if errors:
        print(f"  PIPELINE DONE WITH {len(errors)} ERROR(S):")
        for err in errors:
            print(f"  - {err['step']}: {err['error']}")
    else:
        print("  PIPELINE DONE — No errors.")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    run_pipeline()