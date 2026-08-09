"""Internet public-disclosure scanning for the Novelty gate (plan 2.7).

Automates the "GitHub-outside" part of novelty verification with free,
keyless APIs. Results are converted to `Disclosure` objects and fed into the
existing `NoveltyChecker.evaluate`, so the G3 downgrade logic is unchanged.

Channels:
  * OSV (api.osv.dev)          -- package query, Maven ecosystem
  * NVD (services.nvd.nist.gov) -- keywordSearch (one call per keyword)
  * GitHub repo security-advisories (api.github.com) -- repo-level advisory drafts

Honest limitations (recorded in the result, not hidden):
  * Chinese-only databases (QVD / AVD / LDYVUL) are not in OSV/NVD/GitHub
    advisory databases;
    they still need manual web review or a future adapter.
  * NVD keyword matching is text-based: a generic keyword (e.g. "fastjson")
    can pull records for a different product line (fastjson1), so keywords
    should be target-specific and precise.
  * Network failure / rate-limit degrades to an empty list + error note,
    never a crash, and never a false 0day claim.

Every response is disk-cached (24h TTL) under agent/regression/cache/api/.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..orchestrator.config import TargetConfig
from .novelty import Disclosure

UA = {"User-Agent": "0day-agent-public-scan/1.0"}


class ScanError(Exception):
    """One channel failed; the scanner records it and continues."""


def _cache_key(name: str, payload: str) -> str:
    return hashlib.sha1((name + "|" + payload).encode("utf-8")).hexdigest()


def _read_cache(cache_dir: Optional[Path], key: str, ttl: int = 24 * 3600) -> Optional[Any]:
    if cache_dir is None:
        return None
    f = cache_dir / (key + ".json")
    if not f.exists():
        return None
    try:
        d = json.loads(f.read_text(encoding="utf-8"))
        if time.time() - d.get("fetched_at", 0) < ttl:
            return d.get("data")
    except (OSError, ValueError):
        pass
    return None


def _write_cache(cache_dir: Optional[Path], key: str, data: Any) -> None:
    if cache_dir is None:
        return
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        f = cache_dir / (key + ".json")
        f.write_text(json.dumps({"fetched_at": time.time(), "data": data},
                                ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def _http_json(url: str, method: str = "GET", body: Optional[dict] = None,
               token: Optional[str] = None, timeout: int = 25,
               accept: str = "") -> Any:
    headers = dict(UA)
    if token:
        headers["Authorization"] = "Bearer " + token
    if accept:
        headers["Accept"] = accept
    if method == "POST":
        headers["Content-Type"] = "application/json"
        data = json.dumps(body or {}).encode("utf-8")
    else:
        data = None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def scan_osv(package: str, ecosystem: str = "Maven",
             cache_dir: Optional[Path] = None) -> Tuple[List[Disclosure], str]:
    """OSV package query -> disclosures."""
    key = _cache_key("osv", "%s:%s" % (ecosystem, package))
    cached = _read_cache(cache_dir, key)
    if cached is not None:
        data = cached
    else:
        try:
            data = _http_json(
                "https://api.osv.dev/v1/query", method="POST",
                body={"package": {"ecosystem": ecosystem, "name": package}})
            _write_cache(cache_dir, key, data)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                json.JSONDecodeError) as exc:
            raise ScanError("OSV failed: %s" % type(exc).__name__) from exc
    out = []
    for v in data.get("vulns", []) or []:
        vid = v.get("id") or ""
        if not vid:
            continue
        published = (v.get("published") or v.get("modified") or "")[:10]
        out.append(Disclosure(
            id=vid,
            source="CVE" if vid.startswith("CVE-") else "advisory",
            title=(v.get("summary") or v.get("details") or "")[:200],
            date=published,
            url="https://osv.dev/vulnerability/%s" % vid,
            coverage_note="OSV %s package scan: %s" % (ecosystem, package),
            evidence_source="live OSV API %s" % date.today().isoformat(),
        ))
    return out, "osv=%d" % len(out)


def scan_nvd(keywords: List[str],
             cache_dir: Optional[Path] = None) -> Tuple[List[Disclosure], str]:
    """NVD keywordSearch -> disclosures (one API call per keyword)."""
    out: List[Disclosure] = []
    notes = []
    for kw in keywords or []:
        key = _cache_key("nvd", kw)
        cached = _read_cache(cache_dir, key)
        if cached is not None:
            data = cached
        else:
            try:
                import urllib.parse
                url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
                       "?keywordSearch=%s&resultsPerPage=20"
                       % urllib.parse.quote(kw))
                data = _http_json(url)
                _write_cache(cache_dir, key, data)
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                    json.JSONDecodeError) as exc:
                notes.append("nvd(%s) failed: %s" % (kw, type(exc).__name__))
                continue
        for item in data.get("vulnerabilities", []) or []:
            cve = item.get("cve", {})
            cid = cve.get("id") or ""
            if not cid:
                continue
            descs = cve.get("descriptions") or []
            title = descs[0]["value"][:200] if descs else ""
            out.append(Disclosure(
                id=cid, source="CVE", title=title,
                date=(cve.get("published") or "")[:10],
                url="https://nvd.nist.gov/vuln/detail/%s" % cid,
                coverage_note="NVD keywordSearch: %s" % kw,
                evidence_source="live NVD API %s" % date.today().isoformat(),
            ))
        notes.append("nvd(%s)=%d" % (kw, len(data.get("vulnerabilities", []) or [])))
    return out, "; ".join(notes)


def scan_github_advisories(repo: str, token: Optional[str] = None,
                           cache_dir: Optional[Path] = None) -> Tuple[List[Disclosure], str]:
    """GitHub repo security-advisories -> disclosures."""
    if not repo:
        return [], "github-advisories: no repo"
    token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    key = _cache_key("github-advisories", repo)
    cached = _read_cache(cache_dir, key, ttl=6 * 3600)
    if cached is not None:
        data = cached
    else:
        try:
            data = _http_json(
                "https://api.github.com/repos/%s/security-advisories" % repo,
                token=token, accept="application/vnd.github+json")
            _write_cache(cache_dir, key, data)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                json.JSONDecodeError) as exc:
            raise ScanError("github-advisories failed: %s" % type(exc).__name__) from exc
    out = []
    if isinstance(data, list):
        for adv in data:
            gid = (adv.get("html_url") or "").rstrip("/").split("/")[-1]
            if "-" not in gid:
                gid = adv.get("cve_id") or ""
            if not gid:
                continue
            out.append(Disclosure(
                id=gid, source="advisory",
                title=(adv.get("summary") or "")[:200],
                date=(adv.get("published_at") or adv.get("updated_at")
                      or adv.get("created_at") or "")[:10],
                url=adv.get("html_url") or adv.get("url") or "",
                coverage_note="GitHub repo security-advisories: %s" % repo,
                evidence_source="live GitHub API %s" % date.today().isoformat(),
            ))
    return out, "github-advisories=%d" % len(out)


def scan_all(cfg: TargetConfig, offline: bool = False,
             cache_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Run all configured channels; returns disclosures + per-channel notes.
    Never raises: failed channels are recorded in `errors`."""
    ps = getattr(cfg, "public_scan", None) or {}
    result: Dict[str, Any] = {"disclosures": [], "channels": {}, "errors": []}
    if offline:
        return result
    if not ps:
        return result
    cache_dir = cache_dir or (Path.cwd() / "agent" / "regression" / "cache" / "api")
    pkg = ps.get("maven_package") or ""
    if pkg:
        try:
            disc, note = scan_osv(pkg, ps.get("ecosystem", "Maven"), cache_dir)
            result["disclosures"] += disc
            result["channels"]["osv"] = note
        except ScanError as exc:
            result["errors"].append(str(exc))
    for kw in ps.get("nvd_keywords", []):
        try:
            disc, note = scan_nvd([kw], cache_dir)
            result["disclosures"] += disc
            result["channels"]["nvd:" + kw] = note
        except ScanError as exc:
            result["errors"].append(str(exc))
    repo = ps.get("advisories_repo") or getattr(cfg, "upstream_repo", "") or ""
    if repo:
        try:
            disc, note = scan_github_advisories(repo, cache_dir=cache_dir)
            result["disclosures"] += disc
            result["channels"]["github_advisories"] = note
        except ScanError as exc:
            result["errors"].append(str(exc))
    # dedup by id, keep first
    seen = set()
    dedup = []
    for d in result["disclosures"]:
        if d.id not in seen:
            seen.add(d.id)
            dedup.append(d)
    result["disclosures"] = dedup
    return result
