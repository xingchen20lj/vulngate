"""Novelty gate (S5): upstream issue/PR scan + public disclosure scan + timeline.

Sources, in order:
  1. live GitHub API (read-only); on rate-limit/network failure,
  2. web-verified offline fixtures (regression/fixtures, provenance recorded),
  3. candidate config's static `upstream_refs`/`disclosures`.

Hard rule (G3): any upstream open PR/issue or public disclosure predating the
discovery date downgrades the verdict to known-family-with-increment.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Dict, List, Optional

from ..llm.adapter import BudgetExceeded


class RateLimited(Exception):
    """GitHub API rate limit exhausted (X-RateLimit-Remaining == 0)."""

    def __init__(self, reset_at: Optional[str] = None):
        super().__init__("GitHub API rate limit exhausted")
        self.reset_at = reset_at


@dataclass
class UpstreamRef:
    ref: str
    kind: str            # issue | pull_request | release
    title: str
    state: str           # open | closed | merged
    created_at: str
    url: str
    evidence_source: str = ""
    coverage_note: str = ""   # what it fixes / which paths it does NOT cover
    merged_at: Optional[str] = None
    body: str = ""            # issue/PR body (fetched live; empty when unavailable)
    repo: str = ""            # repo for the ref (defaults to config upstream_repo)

    def predates(self, discovery: str) -> bool:
        try:
            return date.fromisoformat(self.created_at[:10]) <= date.fromisoformat(discovery[:10])
        except ValueError:
            return True


@dataclass
class Disclosure:
    id: str
    source: str          # CVE | QVD | advisory | blog | vuln-db | article
    title: str
    date: str
    url: str
    coverage_note: str = ""
    evidence_source: str = ""


@dataclass
class NoveltyResult:
    verdict: str         # candidate-0day | known-family-with-increment |
                         # upstream-fixed | unknown-query-failed
    reason: str
    increments: List[str]
    refs: List[UpstreamRef] = field(default_factory=list)
    disclosures: List[Disclosure] = field(default_factory=list)
    checked_at: str = ""


class NoveltyChecker:
    API = "https://api.github.com"
    UA = {"User-Agent": "vulngate-novelty-gate/1.0"}

    def __init__(self, fixtures_dir: Optional[Path] = None, offline: bool = False,
                 token: Optional[str] = None, cache_dir: Optional[Path] = None):
        self.fixtures_dir = fixtures_dir
        self.offline = offline
        # Prefer explicit token, then GITHUB_TOKEN / GH_TOKEN (e.g. `gh auth token`).
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.last_rate_limit: Optional[dict] = None

    # ---- live API -------------------------------------------------------
    def _api(self, path: str, ttl_seconds: int = 6 * 3600) -> dict:
        """GET api.github.com+path with auth, disk cache (TTL + ETag) and
        rate-limit detection. 304 responses consume no quota; a fresh cache
        hit consumes none at all."""
        key = hashlib.sha1(path.encode("utf-8")).hexdigest()
        cache_file = self.cache_dir / (key + ".json") if self.cache_dir else None
        cached = self._read_cache(cache_file)

        fresh = cached is not None and time.time() - cached["fetched_at"] < ttl_seconds
        if fresh:
            return cached["data"]

        headers = dict(self.UA)
        if self.token:
            headers["Authorization"] = "Bearer %s" % self.token
        if cached is not None and cached.get("etag"):
            headers["If-None-Match"] = cached["etag"]

        last_exc: Optional[Exception] = None
        for attempt in range(2):
            req = urllib.request.Request(self.API + path, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    self._observe_limits(resp.headers)
                    if resp.status == 304 and cached is not None:
                        self._write_cache(cache_file, path, cached["data"], cached.get("etag"), time.time())
                        return cached["data"]
                    data = json.loads(resp.read().decode("utf-8"))
                    self._write_cache(cache_file, path, data, resp.headers.get("ETag"))
                    return data
            except urllib.error.HTTPError as exc:
                if exc.code == 304 and cached is not None:
                    self._write_cache(cache_file, path, cached["data"], cached.get("etag"), time.time())
                    return cached["data"]
                if exc.headers:
                    self._observe_limits(exc.headers)
                if exc.code == 403 and self.last_rate_limit:
                    raise RateLimited(self.last_rate_limit.get("reset_at")) from exc
                if exc.code >= 500 and attempt == 0:
                    last_exc = exc
                    time.sleep(1.5)
                    continue
                raise
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt == 0:
                    last_exc = exc
                    time.sleep(1.5)
                    continue
                raise
        raise last_exc if last_exc is not None else RuntimeError("unreachable")

    def _observe_limits(self, headers) -> None:
        remaining = headers.get("X-RateLimit-Remaining")
        if remaining == "0":
            self.last_rate_limit = {
                "remaining": 0,
                "reset_at": self._fmt_reset(headers.get("X-RateLimit-Reset")),
            }

    @staticmethod
    def _fmt_reset(raw: Optional[str]) -> str:
        try:
            return datetime.utcfromtimestamp(int(raw)).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError):
            return "unknown"

    def _read_cache(self, cache_file: Optional[Path]) -> Optional[dict]:
        if cache_file is None or not cache_file.exists():
            return None
        try:
            payload = json.loads(cache_file.read_text(encoding="utf-8"))
            if payload.get("path") and isinstance(payload.get("data"), dict) \
                    and isinstance(payload.get("fetched_at"), (int, float)):
                return payload
        except (OSError, ValueError):
            return None
        return None

    def _write_cache(self, cache_file: Optional[Path], path: str, data: dict,
                     etag: Optional[str], fetched_at: Optional[float] = None) -> None:
        if cache_file is None:
            return
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "path": path,
                "etag": etag or "",
                "fetched_at": fetched_at if fetched_at is not None else time.time(),
                "data": data,
            }
            tmp = cache_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            tmp.replace(cache_file)
        except OSError:
            pass

    def _warn_fallback(self, exc: Exception) -> None:
        if isinstance(exc, RateLimited):
            print("[novelty] GitHub API rate-limited (reset ~%s UTC); "
                  "falling back to fixtures/web" % exc.reset_at, file=sys.stderr)
        else:
            print("[novelty] GitHub API error %s; falling back to fixtures/web"
                  % type(exc).__name__, file=sys.stderr)

    def fetch_ref(self, repo: str, number: int, kind: str = "issues") -> Optional[UpstreamRef]:
        if not self.offline:
            try:
                # GitHub REST uses /pulls/{n} for pull requests (/issues/{n}
                # happens to resolve them too, but it is not the documented
                # endpoint). Normalize so any caller passing "pull_request"
                # gets the correct URL (harness fix, 2026-08-09).
                endpoint = "pulls" if kind == "pull_request" else kind
                data = self._api("/repos/%s/%s/%d" % (repo, endpoint, number))
                state = data.get("state")
                if endpoint == "pulls" and data.get("merged_at"):
                    state = "merged"
                return UpstreamRef(
                    ref="#%d" % number, kind=kind, title=data.get("title", ""),
                    state=state, created_at=data.get("created_at", ""),
                    url=data.get("html_url", ""),
                    evidence_source="live GitHub API %s" % datetime.now().date().isoformat(),
                    merged_at=data.get("merged_at"),
                    body=data.get("body", ""),
                )
            except (RateLimited, urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
                self._warn_fallback(exc)
        return self._fixture_ref(repo, number, kind)

    def search(self, repo: str, query: str) -> List[dict]:
        if not self.offline:
            try:
                q = "repo:%s %s" % (repo, query)
                import urllib.parse
                data = self._api("/search/issues?q=" + urllib.parse.quote(q))
                return data.get("items", [])
            except (RateLimited, urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
                self._warn_fallback(exc)
        return self._fixture_search(repo, query)

    # ---- fixtures -------------------------------------------------------
    def _fixture_ref(self, repo: str, number: int, kind: str) -> Optional[UpstreamRef]:
        if self.fixtures_dir is None:
            return None
        f = self.fixtures_dir / ("github-%s-%d.json" % (kind, number))
        if not f.exists():
            f = self.fixtures_dir / ("github-%d.json" % number)
        if not f.exists():
            return None
        data = json.loads(f.read_text(encoding="utf-8"))
        ref = UpstreamRef(
            ref=data.get("ref", "#%d" % number),
            kind=data.get("kind", kind),
            title=data.get("title", ""),
            state=data.get("state", ""),
            created_at=data.get("created_at", ""),
            url=data.get("url", ""),
            evidence_source=data.get("evidence_source", "offline fixture %s" % f.name),
            coverage_note=data.get("coverage_note", ""),
            merged_at=data.get("merged_at"),
            body=data.get("body", ""),
        )
        return ref

    def _fixture_search(self, repo: str, query: str) -> List[dict]:
        if self.fixtures_dir is None:
            return []
        f = self.fixtures_dir / "github-search.json"
        if not f.exists():
            return []
        data = json.loads(f.read_text(encoding="utf-8"))
        hits = []
        for entry in data:
            if query.lower() in entry.get("query", "").lower():
                hits.append(entry)
        return hits

    # ---- evaluation -----------------------------------------------------
    def evaluate(self, refs: List[UpstreamRef], disclosures: List[Disclosure],
                 discovery_date: str, increments_hint: Optional[List[str]] = None,
                 query_failed: bool = False) -> NoveltyResult:
        checked = datetime.now().isoformat(timespec="seconds")
        predating = [r for r in refs if r.predates(discovery_date)]
        open_refs = [r for r in refs if r.state in ("open",)]
        merged = [r for r in refs if r.state == "merged"]
        closed = [r for r in refs if r.state == "closed"]
        hits = predating + open_refs
        disc_hits = [d for d in disclosures if d.date[:10] <= discovery_date[:10]]

        reason_parts = []
        if hits:
            reason_parts.append("upstream record(s) predating discovery: %s"
                                % ", ".join(sorted({r.ref for r in hits})))
        if disc_hits:
            reason_parts.append("public disclosure(s) predating discovery: %s"
                                % ", ".join(sorted({d.id for d in disc_hits})))
        if not hits and not disc_hits:
            if query_failed:
                # Baseline #7: "no record found" is NOT authoritative when the
                # public-information scan itself failed/rate-limited. Must not
                # claim 0day from an incomplete query.
                return NoveltyResult(
                    verdict="unknown-query-failed",
                    reason=("public-info scan incomplete or failed; no record found but "
                            "query was not authoritative (rate-limit/channel errors) -> "
                            "0day claim requires human re-verification"),
                    increments=increments_hint or [],
                    refs=refs,
                    disclosures=disclosures,
                    checked_at=checked,
                )
            return NoveltyResult(
                verdict="candidate-0day",
                reason="no upstream open PR/issue and no public disclosure predating %s" % discovery_date,
                increments=increments_hint or [],
                refs=refs,
                disclosures=disclosures,
                checked_at=checked,
            )

        # Hard downgrade: any hit -> never candidate-0day.
        if hits or disc_hits:
            if not open_refs and merged and not disc_hits:
                verdict = "upstream-fixed"
                reason = "upstream fix merged (%s); " % ", ".join(r.ref for r in merged)
                if not any("released" in (r.coverage_note or "").lower() for r in merged):
                    reason += "release status must be re-checked (merged != released)"
                if hits:
                    reason += " | %s" % "; ".join(reason_parts)
            else:
                verdict = "known-family-with-increment"
                reason = "; ".join(reason_parts)
                if open_refs:
                    reason += " | in-flight upstream fixes: %s" % ", ".join(r.ref for r in open_refs)
        increments = list(increments_hint or [])
        for r in open_refs:
            if r.coverage_note:
                increments.append("%s coverage note: %s" % (r.ref, r.coverage_note))
        return NoveltyResult(
            verdict=verdict,
            reason=reason,
            increments=increments,
            refs=refs,
            disclosures=disclosures,
            checked_at=checked,
        )


def mechanism_audit_llm(llm, system_prompt: str, candidate: Dict,
                        refs: List["UpstreamRef"], checker: "NoveltyChecker",
                        discovery_date, upstream_repo: str,
                        offline: bool = False) -> List[Dict]:
    """S5b: fetch issue/PR bodies for predating hits and have the LLM judge
    whether the upstream record is the SAME vulnerability mechanism as the
    candidate (same trigger, same gadget class, same fix target).
    Shared by the autonomous driver and the config-driven pipeline (optional,
    enabled via config llm_audit). Failures degrade to empty, never crash.
    """
    if offline or not refs or llm is None:
        return []
    if not upstream_repo:
        return []

    def _num(ref: str):
        m = re.search(r"#(\d+)", str(ref))
        return int(m.group(1)) if m else None

    numbered = [r for r in refs if r.predates(discovery_date) and _num(r.ref) is not None][:3]
    if not numbered:
        return []
    bodies = []
    for r in numbered:
        try:
            rrepo = r.repo or upstream_repo
            live = checker.fetch_ref(rrepo, _num(r.ref),
                                     "pulls" if r.kind == "pull_request" else "issues")
            bodies.append({
                "ref": r.ref, "title": (live or r).title,
                "body": ((live or r).body or "(body unavailable)")[:1500],
            })
        except Exception as exc:
            bodies.append({"ref": r.ref, "title": r.title,
                           "body": "(body fetch failed: %s)" % type(exc).__name__})
    user = (
        "候选：%s\n逻辑：%s\n\n上游记录（issue/PR 标题+正文）：\n%s\n\n"
        "逐条判断是否与候选是同一漏洞机制（同一触发点/同一 gadget 类/同一修复对象）。"
        "只输出 JSON：{\"results\":[{\"ref\":\"#N\",\"same_mechanism\":true|false,"
        "\"evidence\":\"一句话依据\"}]}"
        % (candidate.get("surface", ""), candidate.get("logic", ""),
           json.dumps(bodies, ensure_ascii=False)[:6000])
    )
    try:
        data = llm.ask_json(system_prompt, user, max_tokens=1200)
        results = data.get("results") or []
        return [{"ref": str(b.get("ref")), "same_mechanism": bool(b.get("same_mechanism")),
                 "evidence": str(b.get("evidence", ""))[:300]} for b in results][:5]
    except (ValueError, BudgetExceeded) as exc:
        print("[S5b] mechanism audit skipped: %s" % type(exc).__name__)
        return []
