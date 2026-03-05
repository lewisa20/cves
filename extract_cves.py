import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)

def safe_get(obj: Any, path: List[Any], default=None):
    """Safely descend nested dict/list structures."""
    cur = obj
    for p in path:
        if isinstance(p, int):
            if not isinstance(cur, list) or p < 0 or p >= len(cur):
                return default
            cur = cur[p]
        else:
            if not isinstance(cur, dict) or p not in cur:
                return default
            cur = cur[p]
    return cur

def extract_cve_id(rec: Dict[str, Any]) -> Optional[str]:
    return safe_get(rec, ["cveMetadata", "cveId"])

def extract_cvss_scores(rec: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    """
    Return (best_v3_base, best_v4_base).

    Robust across cvelistV5 variations:
      - containers.cna.metrics[*].cvssV3_1 / cvssV3_0 / cvssV4_0
      - containers.adp[*].metrics[*].cvssV3_1 / cvssV3_0 / cvssV4_0
      - Fallback deep scan for cvssV3_1/cvssV3_0/cvssV4_0 objects anywhere in JSON

    Selection rule:
      - If multiple scores exist, returns the MAX baseScore per version family.
        (You can change to "prefer CNA" or "prefer first" if you want.)
    """

    def collect_from_metrics(metrics_list: Any, v3_scores: List[float], v4_scores: List[float]) -> None:
        if not isinstance(metrics_list, list):
            return
        for m in metrics_list:
            if not isinstance(m, dict):
                continue

            # CVSS v4.0
            cvss40 = m.get("cvssV4_0")
            if isinstance(cvss40, dict):
                bs = cvss40.get("baseScore")
                if isinstance(bs, (int, float)):
                    v4_scores.append(float(bs))

            # CVSS v3.1 / v3.0
            for key in ("cvssV3_1", "cvssV3_0"):
                cvss3 = m.get(key)
                if isinstance(cvss3, dict):
                    bs = cvss3.get("baseScore")
                    if isinstance(bs, (int, float)):
                        v3_scores.append(float(bs))

    v3_scores: List[float] = []
    v4_scores: List[float] = []

    # 1) Known location: CNA metrics
    collect_from_metrics(safe_get(rec, ["containers", "cna", "metrics"], default=[]), v3_scores, v4_scores)

    # 2) Known location: ADP metrics (e.g., CISA ADP vulnrichment often stores CVSS here)
    adp_list = safe_get(rec, ["containers", "adp"], default=[]) or []
    if isinstance(adp_list, list):
        for adp in adp_list:
            if isinstance(adp, dict):
                collect_from_metrics(adp.get("metrics"), v3_scores, v4_scores)

    # 3) Fallback: deep scan if we found nothing (covers unusual placements)
    if not v3_scores and not v4_scores:
        def deep_scan(node: Any) -> None:
            if isinstance(node, dict):
                for key, val in node.items():
                    if key in ("cvssV4_0", "cvssV3_1", "cvssV3_0") and isinstance(val, dict):
                        bs = val.get("baseScore")
                        if isinstance(bs, (int, float)):
                            if key == "cvssV4_0":
                                v4_scores.append(float(bs))
                            else:
                                v3_scores.append(float(bs))
                    else:
                        deep_scan(val)
            elif isinstance(node, list):
                for item in node:
                    deep_scan(item)

        deep_scan(rec)

    best_v3 = max(v3_scores) if v3_scores else None
    best_v4 = max(v4_scores) if v4_scores else None
    return best_v3, best_v4

def extract_cwes_from_problemtypes(problem_types: Any) -> Set[str]:
    """
    Extract CWE from:
      - descriptions[*].cweId (clean)
      - descriptions[*].description (messy string containing CWE-xxx)
    """
    cwes: Set[str] = set()
    if not isinstance(problem_types, list):
        return cwes

    for pt in problem_types:
        descs = pt.get("descriptions") if isinstance(pt, dict) else None
        if not isinstance(descs, list):
            continue

        for d in descs:
            if not isinstance(d, dict):
                continue

            # Case 1: explicit cweId field
            cwe_id = d.get("cweId")
            if isinstance(cwe_id, str) and CWE_RE.fullmatch(cwe_id.strip()):
                cwes.add(cwe_id.strip().upper())

            # Case 2: embedded in description
            text = d.get("description")
            if isinstance(text, str):
                for m in CWE_RE.findall(text):
                    cwes.add(m.upper())

    return cwes

def extract_all_cwes(rec: Dict[str, Any]) -> List[str]:
    """Prefer CNA, but also check ADP containers for CWE assignments/enrichments."""
    cwes: Set[str] = set()

    # CNA
    cna_pt = safe_get(rec, ["containers", "cna", "problemTypes"], default=[])
    cwes |= extract_cwes_from_problemtypes(cna_pt)

    # ADP
    adp_list = safe_get(rec, ["containers", "adp"], default=[]) or []
    if isinstance(adp_list, list):
        for adp in adp_list:
            pt = adp.get("problemTypes") if isinstance(adp, dict) else None
            cwes |= extract_cwes_from_problemtypes(pt)

    return sorted(cwes)

def iter_cve_json_files(root: Path) -> Iterable[Path]:
    """Recursively find all CVE JSON files under root."""
    yield from root.rglob("CVE-*.json")

def load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract CVE ID, CVSS (v3.x/v4.0), and CWE(s) from cvelistV5 local JSON tree."
    )
    parser.add_argument("--root", required=True, help="Path to your local 'cves' folder (or a single year folder)")
    parser.add_argument("--out", default="cve_cvss_cwe.csv", help="Output CSV filename")
    parser.add_argument("--limit", type=int, default=0, help="For testing: stop after N records (0 = no limit)")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_path = Path(args.out).resolve()

    if not root.exists():
        raise SystemExit(f"Root path does not exist: {root}")

    # Ensure output directory exists (prevents FileNotFoundError when using output subfolders)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["CVE", "CVSSv3.x", "CVSSv4.0", "BestCVSS", "CWEs"])

        for p in iter_cve_json_files(root):
            rec = load_json(p)
            if not isinstance(rec, dict):
                continue

            cve_id = extract_cve_id(rec)
            if not cve_id:
                continue

            v3, v4 = extract_cvss_scores(rec)
            best = v4 if v4 is not None else v3
            cwes = extract_all_cwes(rec)

            writer.writerow([
                cve_id,
                "" if v3 is None else v3,
                "" if v4 is None else v4,
                "" if best is None else best,
                ";".join(cwes),
            ])

            count += 1
            if args.limit and count >= args.limit:
                break
            if count % 1000 == 0:
                print(f"Processed {count} CVEs...")

    print(f"Done. Wrote {count} rows to {out_path}")

if __name__ == "__main__":
    main()
