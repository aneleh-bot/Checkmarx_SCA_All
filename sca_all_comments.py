import requests
import time
import re
import os
import json
import base64
import pandas as pd
from datetime import datetime, timedelta, timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import HTTPError, ChunkedEncodingError, ConnectionError, ReadTimeout, ConnectTimeout
from urllib.parse import quote
import argparse
from typing import Optional, Set, Tuple, Dict, Any, Iterable

# --------------------------------------------------
# Settings (replace!)
# --------------------------------------------------
AST_API_BASE   = "https://us.ast.checkmarx.net"          # AST (Projects/Scans/Results) - client URL (US,US2,EU,EU2) <-------------
SCA_API_BASE   = "https://us.api-sca.checkmarx.net"      # SCA Risk Management (comments/notes/history) - client URL (US,US2,EU,EU2) <-------------
CLIENT_ID = " " # client ID - Checkmarx OAuth <-------------
CLIENT_SECRET = " " # client secret - Checkmarx OAuth <-------------
TENANT_NAME = " "
# --------------------------------------------------

AUTH_URL       = f"https://us.iam.checkmarx.net/auth/realms/{TENANT_NAME}/protocol/openid-connect/token"
PROJECTS_URL   = f"{AST_API_BASE}/api/projects"
SCANS_URL      = f"{AST_API_BASE}/api/scans"
RESULTS_URL    = f"{AST_API_BASE}/api/results"

# GraphQL for SCA/MOR
SCA_GQL_URL    = f"{AST_API_BASE}/api/sca/graphql/graphql"

# ------------------------------------------------
# Defaults (replace!)
# ------------------------------------------------
DEFAULT_LOOKBACK_DAYS = 30    # <---------- 30 days by default, client can choose the number
# ------------------------------------------------
 
PAGE_SIZE = 1000              
HISTORY_CSV = ""              # example: r"C:\temp\risk_history.csv" (optional offline merge)
MAX_RPS_GQL = 2.0             
WINDOW_DAYS = 7             

# =========================
# SESSION + AUTH
# =========================
session = requests.Session()
session.mount("https://", HTTPAdapter(max_retries=Retry(
    total=5, backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "POST"]
)))

# simple token cache
_token_cache: Dict[str, Any] = {"token": None, "expires_at": 0.0}

def get_headers() -> Dict[str, str]:
    now = time.time()
    if _token_cache["token"] and now < float(_token_cache["expires_at"]):
        return {"Authorization": f"Bearer {_token_cache['token']}", "Accept": "application/json;v=1.0"}
    r = session.post(
        AUTH_URL,
        data={"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
        timeout=(5, 30)
    )
    r.raise_for_status()
    data = r.json()
    token = data["access_token"]
    _token_cache["token"] = token
    _token_cache["expires_at"] = now + data.get("expires_in", 3600) - 60
    return {"Authorization": f"Bearer {token}", "Accept": "application/json;v=1.0"}

# =========================
# HELPERS
# =========================
CONFIRM_PAT = re.compile(r"\bconfirm(?:ed|ation|ar|ado|ação|acao)?\b", re.I)

def _is_confirmed(res: Dict[str, Any]) -> bool:
    for k in ("state", "validationState", "resultState", "status"):
        v = res.get(k)
        if isinstance(v, str) and v.strip().lower() == "confirmed":
            return True
    return False

def _is_sca(res: Dict[str, Any]) -> bool:
    if (res.get("type") or "").lower() == "sca":
        return True
    return bool((res.get("data") or {}).get("packageIdentifier"))

def _result_id(r: Dict[str, Any]) -> str:
    return str(r.get("id") or r.get("resultId") or r.get("alternateId") or r.get("similarityId") or "")

def _safe_first_line(s: str) -> str:
    return (s or "").split("\n", 1)[0].strip()

# -------------------------
# Parse packageIdentifier -> (manager, name, version)
# -------------------------
def parse_pkg(identifier: str) -> Tuple[str, str, str]:
    if not identifier:
        return "", "", ""
    ident = str(identifier)
    if ident.startswith(("Npm-", "npm-")):
        parts = ident.split("-", 2)
        if len(parts) == 3:
            return parts[0].replace("npm", "Npm"), parts[1], parts[2]
    if ident.startswith(("Maven-", "maven-")):
        # Maven-<group:artifact>-<version> (the name may contain ':') —> use the last "-" as the version separator
        try:
            last_dash = ident.rindex("-")
            manager = ident[:ident.index("-")]
            name = ident[len(manager) + 1:last_dash]
            version = ident[last_dash + 1:]
            manager = manager.replace("maven", "Maven")
            return manager, name, version
        except ValueError:
            pass
    # generic fallback: Manager-name-version (3 parts)
    parts = ident.split("-", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    return "", "", ""

# ========================================
# GRAPHQL (rate limit and cache)
# ========================================
GQL_QUERY = """
query ($scanId: UUID!, $projectId: String, $isLatest: Boolean!, $packageName: String, $packageVersion: String, $packageManager: String, $vulnerabilityId: String) {
  searchPackageVulnerabilityStateAndScoreActions(
    scanId: $scanId,
    projectId: $projectId,
    isLatest: $isLatest,
    packageName: $packageName,
    packageVersion: $packageVersion,
    packageManager: $packageManager,
    vulnerabilityId: $vulnerabilityId
  ) {
    actions {
      isComment
      actionType
      actionValue
      previousActionValue
      enabled
      createdAt
      comment { id message createdOn userName }
    }
  }
}
""".strip()

_last_gql_call = 0.0
_gql_cache: Dict[Tuple[str, str, str, str, str, str], Tuple[str, str, str]] = {}

def _gql_rate_limit():
    global _last_gql_call
    gap = 1.0 / max(0.1, float(MAX_RPS_GQL))
    now = time.time()
    wait = _last_gql_call + gap - now
    if wait > 0:
        time.sleep(wait)
    _last_gql_call = time.time()

def _author_from_graphql(headers: Dict[str, str], project_id: str, scan_id: str, res: Dict[str, Any]) -> Tuple[str, str, str]:
    # extract variables
    pkg_id = (res.get("data") or {}).get("packageIdentifier") or ""
    manager, pkg_name, pkg_ver = parse_pkg(pkg_id)
    cve = (res.get("vulnerabilityDetails") or {}).get("cveName") or ""

    cache_key = (project_id, scan_id, manager, pkg_name, pkg_ver, cve)
    if cache_key in _gql_cache:
        return _gql_cache[cache_key]

    variables = {
        "scanId": scan_id,
        "projectId": project_id,
        "isLatest": True,
        "packageName": pkg_name or None,
        "packageVersion": pkg_ver or None,
        "packageManager": manager or None,
        "vulnerabilityId": cve or None,
    }

    payload = {"query": GQL_QUERY, "variables": variables}
    hdrs = dict(headers)
    hdrs["Accept"] = "application/json"
    hdrs["Content-Type"] = "application/json"

    # rate limit
    _gql_rate_limit()

    try:
        r = session.post(SCA_GQL_URL, headers=hdrs, json=payload, timeout=(5, 30))
        status = r.status_code
        if status != 200:
            print(f"[GQL {status}] erro ao consultar ações.")
            out = ("", f"GQL_HTTP_{status}", "")
            _gql_cache[cache_key] = out
            return out
        data = r.json()
    except Exception as e:
        print(f"[GQL ERR] {e}")
        out = ("", "GQL_ERR", "")
        _gql_cache[cache_key] = out
        return out

    # graphQL errors (even with HTTP 200)
    if "errors" in data and data["errors"]:
        e0 = data["errors"][0]
        print(f"[GQL ERROR] {e0.get('message')}")
        out = ("", "GQL_ERRORS", "")
        _gql_cache[cache_key] = out
        return out

    actions = (((data.get("data") or {}).get("searchPackageVulnerabilityStateAndScoreActions") or {}).get("actions")) or []
    if not actions:
        out = ("", "GQL_EMPTY", "")
        _gql_cache[cache_key] = out
        return out

    # sort by createdAt (asc) and decides the "best" one
    def to_dt(s: Any) -> datetime:
        try:
            return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    actions.sort(key=lambda a: to_dt(a.get("createdAt")))

    # 1) prioritizes change action to Confirmed OR comment containing "confirm"
    best = None
    for a in reversed(actions):
        action_val = str(a.get("actionValue") or "").strip().lower()
        prev_val   = str(a.get("previousActionValue") or "").strip().lower()
        msg        = ((a.get("comment") or {}).get("message") or "")
        if action_val == "confirmed" or (prev_val == "to verify" and action_val):
            best = a
            break
        if CONFIRM_PAT.search(msg):
            best = a
            break

    # 2) otherwise, take the last entry with comment.userName
    if not best:
        for a in reversed(actions):
            if (a.get("comment") or {}).get("userName"):
                best = a
                break

    if not best:
        out = ("", "GQL_NO_MATCH", "")
        _gql_cache[cache_key] = out
        return out

    author = ((best.get("comment") or {}).get("userName") or "").strip()
    confirm_note = ""
    try:
        c = best.get("comment") or {}
        if isinstance(c, dict):
            confirm_note = str(c.get("message") or c.get("text") or c.get("note") or "").strip()
        elif isinstance(c, (str, bytes)):
            confirm_note = str(c).strip()
    except Exception:
        pass
    if not confirm_note:
        confirm_note = str(best.get("message") or best.get("text") or best.get("note") or best.get("body") or "").strip()

    out = (author, "GQL_actions", confirm_note)
    _gql_cache[cache_key] = out
    return out

# =========================
# MERGE CSV --- optional
# =========================
class HistoryIndex:
    def __init__(self):
        self.idx: Dict[Tuple[str, str], list] = {}

    def add(self, row: Dict[str, Any], pid: str):
        def g(*names: str) -> str:
            for n in names:
                v = row.get(n)
                if pd.notna(v) and str(v).strip():
                    return str(v).strip()
            return ""
        keys = [
            g("riskId", "entityId", "riskID"),
            g("cve", "cveName", "CVE"),
            g("package", "packageIdentifier"),
            g("resultId"),
            g("similarityId"),
            g("alternateId", "altId"),
        ]
        keys = [k for k in keys if k]
        for k in list(keys):
            for b in _b64_variants(k):
                keys.append(b)
        for k in keys:
            self.idx.setdefault((pid, k.lower()), []).append(row)

    def find(self, pid: str, candidates: Iterable[str]):
        for c in candidates:
            if not c:
                continue
            hit = self.idx.get((pid, str(c).lower()))
            if hit:
                return hit
        return None

def _b64_variants(s: str) -> Set[str]:
    out: Set[str] = set()
    if not s:
        return out
    raw = str(s).encode("utf-8")
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        t = enc(raw).decode("ascii")
        out.add(t)
        out.add(t.rstrip("="))
    return out

def load_history_index(csv_path: str) -> Optional[HistoryIndex]:
    if not csv_path:
        return None
    if not os.path.exists(csv_path):
        print(f"[CSV MERGE] file '{csv_path}' not found - offline merge disabled.")
        return None
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[CSV MERGE] failed to read '{csv_path}': {e}")
        return None
    idx = HistoryIndex()
    for _, row in df.iterrows():
        d = {str(k).strip(): (None if pd.isna(v) else v) for k, v in row.items()}
        # tenta encontrar projectId na linha
        pid = ""
        for cand in ("projectId", "ProjectId", "project_id", "projectID"):
            if cand in d and d[cand]:
                pid = str(d[cand]).strip()
                break
        idx.add(d, pid or "")
    print(f"[CSV MERGE] carregado '{csv_path}' com {len(df)} linhas.")
    return idx

# =========================
# PAGINATION (AST)
# =========================
def list_projects(headers: Dict[str, str]):
    acc, off = [], 0
    while True:
        r = session.get(PROJECTS_URL, headers=headers, params={"limit": PAGE_SIZE, "offset": off}, timeout=(5, 30))
        r.raise_for_status()
        batch = r.json().get("projects", [])
        if not batch:
            break
        acc += batch
        off += PAGE_SIZE
    return acc

def list_scans_for_project(headers: Dict[str, str], project_id: str, from_iso: str):
    acc, off = [], 0
    tried_refresh = False
    while True:
        try:
            r = session.get(
                SCANS_URL,
                headers=headers,
                timeout=(5, 30),
                params={"project-id": project_id, "from-date": from_iso, "limit": PAGE_SIZE, "offset": off}
            )
            if r.status_code == 401 and not tried_refresh:
                print("[WARN] 401 on /scans; renewing token and retrying…")
                headers = get_headers()
                tried_refresh = True
                continue
            r.raise_for_status()
        except HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                print(f"[WARN] not authorized for project {project_id}, skipping.")
                return []
            raise
        batch = r.json().get("scans", [])
        if not batch:
            break
        acc += batch
        off += PAGE_SIZE
    return acc

def get_results_for_scan(headers: Dict[str, str], scan_id: str):
    acc, off = [], 0
    tried_refresh = False
    while True:
        try:
            r = session.get(
                RESULTS_URL,
                headers=headers,
                timeout=(10, 60),
                params={
                    "scan-id": scan_id,
                    "limit": PAGE_SIZE,
                    "offset": off,
                    "includeNotes": "true",
                    "includeComments": "true",
                    "includeHistory": "true",
                    "includeValidation": "true",
                }
            )
            # if the token expired during processing, 401 appears here
            if r.status_code == 401 and not tried_refresh:
                print("[WARN] 401 on /results; token may have expired. Renewing and retrying…")
                headers = get_headers()  # catch a new token
                tried_refresh = True
                continue                   # retry the request with a new token
            r.raise_for_status()
            batch = r.json().get("results", [])
        except (ChunkedEncodingError, ConnectionError, ReadTimeout, ConnectTimeout) as e:
            print(f"[WARN] conection/timeout offset {off}: {e}. re-trying...")
            time.sleep(3)
            continue
        except HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            print(f"[WARN] HTTP {code} on /results for scan {scan_id}; skipping this scan.")
            break
        if not batch:
            break
        acc += batch
        off += PAGE_SIZE
    return acc

# =========================
# COLLECTION 
# =========================
def daterange_windows(days: int, window_days: int):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    cur = start
    while cur < end:
        yield cur
        cur += timedelta(days=window_days)

def collect_sca_findings(days: int, window_days: int, target_projects: Optional[Set[str]] = None) -> pd.DataFrame:
    headers = get_headers()
    projects = list_projects(headers)

    if target_projects:
        projects = [p for p in projects if p.get("name") in target_projects or p.get("id") in target_projects]

    print(f"Projects considered: {len(projects)}")

    hist_idx = load_history_index(HISTORY_CSV)

    rows = []
    seen_scans: Set[str] = set()

    for proj in projects:
        headers = get_headers()
        pid = proj.get("id")
        pname = proj.get("name", "<unknown>")
        print(f"\n[PROJ] {pname} ({pid})")

        for win_start in daterange_windows(days, window_days):
            from_iso = win_start.strftime("%Y-%m-%dT%H:%M:%SZ")
            scans = list_scans_for_project(headers, pid, from_iso)
            # deduplicate scans already seen in previous windows
            new_scans = [s for s in scans if s.get("id") not in seen_scans]
            for s in new_scans:
                if s.get("id"):
                    seen_scans.add(s.get("id"))

            print(f"  janela desde {from_iso}: {len(new_scans)} scans novos")

            for scan in new_scans:
                sid = scan.get("id")
                # ensure a fresh token before fetching results
                headers = get_headers()
                results = get_results_for_scan(headers, sid)
                sca_results = [r for r in results if _is_sca(r)]
                if not sca_results:
                    continue
                print(f"    Scan {sid}: {len(sca_results)} SCA")

                for res in sca_results:
                    rid = _result_id(res)
                    vuln = (
                        res.get("vulnerabilityDetails", {}).get("cveName")
                        or (res.get("data", {}).get("packageIdentifier") or _safe_first_line(res.get("description", "")))
                    )

                    author, source, confirm_note = _author_from_graphql(headers, pid, sid, res)

                    if not author and hist_idx is not None:
                        candidates = []
                        candidates += [res.get("alternateId") or ""]
                        candidates += [rid, str(res.get("similarityId") or "")]
                        candidates += [(res.get("data") or {}).get("packageIdentifier") or ""]
                        candidates += [(res.get("vulnerabilityDetails") or {}).get("cveName") or ""]
                        candidates = [c for c in candidates if c]
                        hit = hist_idx.find(pid or "", candidates)
                        if hit:
                            last = list(hit)[-1]
                            author = str(last.get("author") or last.get("createdBy") or last.get("userName") or "").strip()
                            if author:
                                source = "CSV_MERGE"

                    if not author:
                        print(f"      [AUTHOR EMPTY] pid={pid} rid={rid} cve/pkg={vuln} source={source}")

                    rows.append({
                        "Project Name":   pname,
                        "Project Id":     pid,
                        "Scan Id":        sid,
                        "Result Id":      rid,
                        "CVE/Package":    vuln,
                        "Severity":       res.get("severity", ""),
                        "State":          res.get("state") or res.get("validationState") or res.get("resultState") or res.get("status", ""),
                        "Confirmed":      _is_confirmed(res),
                        "Author":         author,
                        "Author Source":  source,
                        "Detected First": res.get("firstFoundAt", ""),
                        "Detected Last":  res.get("foundAt", "") or res.get("lastFoundAt", "") or res.get("updatedAt", ""),
                        "Confirm Note":   confirm_note or ""
                    })

    return pd.DataFrame(rows)

# =========================
# EXPORT
# =========================
def export_report(df: pd.DataFrame, excel_file: str = "checkmarx_sca_all.xlsx", csv_also: bool = True):
    if df.empty:
        print("No SCA vulnerabilities found.")
        return
    # for large volumes, prioritize CSV as well
    try:
        with pd.ExcelWriter(excel_file, engine="openpyxl") as w:
            df.to_excel(w, sheet_name="SCA All", index=False)
        print(f"Report generated: {excel_file}")
    except PermissionError:
        base, ext = os.path.splitext(excel_file)
        alt = f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
        with pd.ExcelWriter(alt, engine="openpyxl") as w:
            df.to_excel(w, sheet_name="SCA All", index=False)
        print(f"[WARN] '{excel_file}' is in use. Saved as: {alt}")
    if csv_also:
        try:
            csv_name = os.path.splitext(excel_file)[0] + ".csv"
            df.to_csv(csv_name, index=False)
            print(f"CSV generated: {csv_name}")
        except Exception as e:
            print(f"[WARN] failed to generate auxiliary CSV: {e}")

# =========================
# CLI
# =========================
def parse_args():
    p = argparse.ArgumentParser(description='Exports SCA vulnerabilities (all) with author/comment via GraphQL.')
    p.add_argument('--days', type=int, default=DEFAULT_LOOKBACK_DAYS, help='Lookback window in days (ex.: 30)')
    p.add_argument('--window-days', type=int, default=WINDOW_DAYS, help='Window size in days for partitioning queries (ex.: 7)')
    p.add_argument('--output', default='checkmarx_sca_all.xlsx', help='Output file name (Excel)')
    p.add_argument('--projects', default='', help='Comma-separated list of project names/IDs to filter')
    p.add_argument('--max-rps-gql', type=float, default=MAX_RPS_GQL, help='RPS limit for GraphQL calls')
    return p.parse_args()

if __name__ == "__main__":
    for var in ("CLIENT_ID", "CLIENT_SECRET", "TENANT_NAME"):
        if not globals()[var].strip():
            raise ValueError(f"⚠️ Configuração faltando: {var}")

    args = parse_args()
    MAX_RPS_GQL = float(args.max_rps_gql)

    targets = set([s.strip() for s in args.projects.split(",") if s.strip()]) or None

    df = collect_sca_findings(days=args.days, window_days=args.window_days, target_projects=targets)
    export_report(df, excel_file=args.output)

    if not df.empty:
        print("\n=== SCA All (Include Confirmed and other states) ===")
        print(df[["Project Name", "CVE/Package", "Severity", "State", "Confirmed", "Author", "Author Source"]])