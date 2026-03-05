"""
Enrich the CISA KEV catalogue CSV with NVD CVE publish dates, then compute
the empirical distribution of KEV inclusion delay.

Inputs:
  - kev_catalog.csv  (must contain columns: cveID, dateAdded)

Outputs:
  - kev_with_publish_dates_partial.csv         (checkpoint, overwritten)
  - kev_with_publish_dates.csv                 (final with publishedDate)
  - kev_with_publish_dates_and_delay.csv       (final + delay_days)
  - delay_summary.txt                          (basic stats)
  - delay_ecdf.csv                             (empirical CDF points)

Notes:
  - Uses NVD API v2 endpoint: /rest/json/cves/2.0
  - dateAdded in KEV is usually YYYY-MM-DD; set DAYFIRST=True if yours is UK-style.
  - NVD rate limits apply; this script throttles requests and retries on 429/5xx.
"""

from __future__ import annotations

import os
import time
from typing import Optional

import pandas as pd
import requests


# -----------------------------
# User-configurable settings
# -----------------------------
KEV_CSV_IN = "kev_catalog.csv"

OUT_PARTIAL = "kev_with_publish_dates_partial.csv"
OUT_PUBLISHED = "kev_with_publish_dates.csv"
OUT_DELAY = "kev_with_publish_dates_and_delay.csv"
OUT_SUMMARY = "delay_summary.txt"
OUT_ECDF = "delay_ecdf.csv"

# If your KEV dateAdded is in UK format like "03/03/2026", set True
DAYFIRST = False

# Throttling / retries
SLEEP_SECONDS = 1.2           # increase to 2.0 if you see many 429s
MAX_RETRIES = 6
CHECKPOINT_EVERY = 50         # write partial CSV every N CVEs
PRINT_EVERY = 50              # progress logging

# Optional: set an NVD API key via environment variable to increase rate limits:
#   setx NVD_API_KEY "your_key_here"
NVD_API_KEY = os.getenv("NVD_API_KEY")  # or replace with a string

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "kev-delay-study/1.0 (academic research)"


# -----------------------------
# NVD lookup
# -----------------------------
def get_publish_date(cve_id: str, api_key: Optional[str] = None) -> Optional[str]:
    """
    Fetch NVD published date for a CVE.
    Returns 'YYYY-MM-DD' or None if unavailable.
    Retries on 429 and transient 5xx errors with exponential backoff.
    """
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key

    params = {"cveId": cve_id}

    backoff = 1.0
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=30)

            # Handle throttling / transient errors
            if r.status_code in (429, 500, 502, 503, 504):
                print(f"[{cve_id}] HTTP {r.status_code} (retry {attempt}/{MAX_RETRIES})")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            if r.status_code != 200:
                snippet = r.text[:160].replace("\n", " ")
                print(f"[{cve_id}] HTTP {r.status_code}: {snippet}")
                return None

            # Make sure it's JSON (some gateways return HTML)
            ct = (r.headers.get("Content-Type") or "").lower()
            if "json" not in ct:
                snippet = r.text[:160].replace("\n", " ")
                print(f"[{cve_id}] Non-JSON response Content-Type={ct}: {snippet}")
                return None

            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                # CVE may not be present in NVD yet
                print(f"[{cve_id}] Not found in NVD (empty vulnerabilities).")
                return None

            published = vulns[0].get("cve", {}).get("published")
            if not published:
                print(f"[{cve_id}] Missing 'published' in NVD record.")
                return None

            return published[:10]  # YYYY-MM-DD

        except requests.exceptions.RequestException as e:
            print(f"[{cve_id}] Request error: {e} (retry {attempt}/{MAX_RETRIES})")
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
        except ValueError as e:
            # JSON decoding error
            snippet = r.text[:160].replace("\n", " ") if "r" in locals() else ""
            print(f"[{cve_id}] JSON parse error: {e}. Response starts: {snippet}")
            return None

    print(f"[{cve_id}] Failed after {MAX_RETRIES} retries.")
    return None


# -----------------------------
# ECDF helper
# -----------------------------
def compute_ecdf(series: pd.Series) -> pd.DataFrame:
    """
    Empirical CDF for a numeric series.
    Returns DataFrame with columns: x, F
    """
    s = series.dropna().astype(float).sort_values().reset_index(drop=True)
    n = len(s)
    if n == 0:
        return pd.DataFrame({"x": [], "F": []})
    F = (pd.Series(range(1, n + 1)) / n).astype(float)
    return pd.DataFrame({"x": s, "F": F})


# -----------------------------
# Main pipeline
# -----------------------------
def main() -> None:
    kev = pd.read_csv(KEV_CSV_IN)

    if "cveID" not in kev.columns:
        raise ValueError(f"Expected column 'cveID' in {KEV_CSV_IN}. Found: {list(kev.columns)}")
    if "dateAdded" not in kev.columns:
        raise ValueError(f"Expected column 'dateAdded' in {KEV_CSV_IN}. Found: {list(kev.columns)}")

    # Prepare target column
    if "publishedDate" not in kev.columns:
        kev["publishedDate"] = pd.NA

    # Optional: if you're re-running, skip rows already filled
    # (handy if you stopped mid-run)
    total = len(kev)
    for idx in range(total):
        cve_id = str(kev.loc[idx, "cveID"])

        if pd.notna(kev.loc[idx, "publishedDate"]) and str(kev.loc[idx, "publishedDate"]).strip() != "":
            continue  # already have it

        print(f"Querying {cve_id}")
        pub = get_publish_date(cve_id, api_key=NVD_API_KEY)
        kev.loc[idx, "publishedDate"] = pub

        # Heartbeat / checkpoint
        i = idx + 1
        if i % PRINT_EVERY == 0:
            sample = kev.loc[idx, "publishedDate"]
            print(f"Processed {i}/{total} | latest publishedDate={sample}")

        if i % CHECKPOINT_EVERY == 0:
            kev.to_csv(OUT_PARTIAL, index=False)
            print(f"Saved checkpoint: {OUT_PARTIAL} (rows processed: {i})")

        time.sleep(SLEEP_SECONDS)

    # Save final with published dates
    kev.to_csv(OUT_PUBLISHED, index=False)
    print(f"Done. Wrote: {OUT_PUBLISHED}")

    # Compute delay in days
    kev["dateAdded_dt"] = pd.to_datetime(kev["dateAdded"], dayfirst=DAYFIRST, errors="coerce")
    kev["publishedDate_dt"] = pd.to_datetime(kev["publishedDate"], errors="coerce")
    kev["delay_days"] = (kev["dateAdded_dt"] - kev["publishedDate_dt"]).dt.days

    kev.to_csv(OUT_DELAY, index=False)
    print(f"Wrote: {OUT_DELAY}")

    # Summaries for the delay distribution
    delays = kev["delay_days"].dropna()
    summary = delays.describe(percentiles=[0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99])

    with open(OUT_SUMMARY, "w", encoding="utf-8") as f:
        f.write("Empirical distribution of delay_days = dateAdded - publishedDate\n")
        f.write(f"Rows total: {len(kev)}\n")
        f.write(f"Rows with delay_days: {len(delays)}\n\n")
        f.write(summary.to_string())
        f.write("\n")

    print(f"Wrote: {OUT_SUMMARY}")

    # ECDF points (x=delay_days, F=cumulative probability)
    ecdf = compute_ecdf(kev["delay_days"])
    ecdf.to_csv(OUT_ECDF, index=False)
    print(f"Wrote: {OUT_ECDF}")


if __name__ == "__main__":
    main()