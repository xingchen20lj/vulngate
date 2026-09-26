"""Target preparation and bounded source inventory."""

from __future__ import annotations

# The phase modules share a deliberately centralized policy/context namespace.
# Keep this import surface stable while the public facade preserves legacy callers.
# ruff: noqa: F403,F405
from .common import *
from .common import _target_source_scope

def _is_web_target(target_dir: Path, timeout: float = 30) -> bool:
    """Heuristic target-type detection (observable facts only)."""
    markers = ("compojure", "ring/ring", "javax.servlet", "jakarta.servlet",
               "spring-boot", "SpringBootApplication", "flask", "django",
               "express", "dispatcher", "defroutes", "defendpoint")
    env_md = target_dir / "env.md"
    if env_md.exists():
        text = env_md.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if line.strip().lower().startswith("target_type:"):
                tt = line.split(":", 1)[1].strip().lower()
                return tt in ("web-app", "webapp", "web", "application")
    try:
        hits = subprocess.run(
            ["rg", "-l", "-m", "1", "|".join(markers), str(target_dir)],
            capture_output=True, text=True, timeout=timeout).stdout
        return bool(hits.strip())
    except subprocess.TimeoutExpired as exc:
        raise TargetPreparationTimeout({
            "stage": "target-type-detection", "current_path": str(target_dir),
            "error": "target-type scan timed out", "claim_status": "not-a-finding",
        }) from exc
    except Exception:
        return False


def scan_all_http_entries(source_dirs: List[Path], timeout: float = 600
                          ) -> List[Dict[str, Any]]:
    """Web-app entry inventory: **every** route/controller declaration found.

    Split from :func:`scan_http_entries` per spec §6.1 -- this half is uncapped
    and is what the coverage index is built from; the other half exists only to
    keep a prompt/report bounded.
    """
    pat = SOURCE_MAP_PRESETS.get("http", r"defendpoint|defroutes|doGet|doPost")
    entries: List[Dict[str, Any]] = []
    seen = set()
    deadline = time.monotonic() + max(0.0, float(timeout))
    for sd in source_dirs:
        if not sd.exists():
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TargetPreparationTimeout({
                "stage": "http-entry-scan", "current_path": str(sd),
                "error": "shared HTTP entry scan deadline exhausted",
                "claim_status": "not-a-finding",
            })
        try:
            hits = se.scan_all_hits(pat, [sd.as_posix()], sd.parent,
                                    timeout=remaining)
        except se.SourceScanTimeout as exc:
            raise TargetPreparationTimeout({
                "stage": "http-entry-scan", "current_path": str(sd),
                "error": str(exc), "scan_progress": exc.progress,
                "claim_status": "not-a-finding",
            }) from exc
        for hit in hits:
            if time.monotonic() >= deadline:
                raise TargetPreparationTimeout({
                    "stage": "http-entry-scan", "current_path": str(hit["file"]),
                    "error": "HTTP entry classification exceeded its shared deadline",
                    "claim_status": "not-a-finding",
                })
            key = (hit["file"], hit["line"])
            if key in seen:
                continue
            seen.add(key)
            entries.append({
                "api": "http-route",
                "input_shape": "http-request",
                "file_line": "%s:%d" % (hit["file"], hit["line"]),
                "untrusted": True,
                "text": hit["text"],
                "entry_kind": "http",
                "module": str(hit["file"]).split("/")[0],
            })
    entries.sort(key=lambda e: str(e["file_line"]))
    if time.monotonic() >= deadline:
        raise TargetPreparationTimeout({
            "stage": "http-entry-scan",
            "current_path": str(source_dirs[-1] if source_dirs else Path(".")),
            "error": "HTTP entry inventory sorting exceeded its shared deadline",
            "claim_status": "not-a-finding",
        })
    return entries


def scan_http_entries(source_dirs: List[Path],
                      max_items: int = 200) -> List[Dict[str, Any]]:
    """Bounded web entry digest for configs/prompts.  **Not** an index."""
    return summarize_hits(scan_all_http_entries(source_dirs), max_items)



ENTRY_API_PATTERNS = [
    (r"\breadValue\s*\(", "json deserialization entry (ObjectMapper)"),
    (r"\breadTree\s*\(", "json tree parse entry"),
    (r"\bparseObject\s*\(", "text/json, typed object parse"),
    (r"\bfromJson\s*\(", "json parse"),
    (r"\bfromXml\s*\(", "text/xml object parse"),
    (r"\bfromXML\s*\(", "text/xml object parse"),
    (r"\bunmarshal\s*\(", "stream/xml unmarshal"),
    (r"\bdecodeObject\s*\(", "binary object parse"),
    (r"\breadObject\s*\(", "stream object parse"),
    (r"\bparse\s*\(", "text/json parse (generic)"),
]

#: Combined danger-pattern regex, used to score an entry file's danger density.
#: Counting from the file text once (rather than one ``rg -c`` per file) keeps
#: the now-uncapped entry scan affordable.
_DANGER_COMBINED = re.compile("|".join("(?:%s)" % p for p, _ in DANGER_PATTERNS))


def _danger_hit_count(path: Path, cache: Dict[str, int]) -> int:
    key = path.as_posix()
    if key in cache:
        return cache[key]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        count = len(_DANGER_COMBINED.findall(text))
    except OSError:
        count = 0
    cache[key] = count
    return count


def scan_all_entries(source_dirs: List[Path], timeout: float = 600
                     ) -> List[Dict[str, Any]]:
    """**Full** entry inventory: every hit of every entry-API pattern.

    The previous implementation stopped at ``per_pattern=5`` and
    ``len(entries) >= 20``, so a target with 400 parse call sites reported 20
    entries and the remaining 380 never entered any audit state (spec §6.1).
    The caps now live only in :func:`scan_entries`. All API patterns are
    classified from one combined ripgrep pass so preparation has one shared
    scan deadline instead of rescanning the full tree once per API.
    """
    entries: List[Dict[str, Any]] = []
    seen = set()
    danger_cache: Dict[str, int] = {}
    scan_roots = [(Path(os.path.abspath(src)), Path(os.path.abspath(src)).resolve())
                  for src in source_dirs if src.exists()]
    if not scan_roots:
        return entries
    deadline = time.monotonic() + max(0.0, float(timeout))
    scan_root = Path(os.path.commonpath([str(src) for src, _resolved in scan_roots]))
    source_relpaths = [Path(os.path.relpath(src, scan_root)).as_posix()
                       for src, _resolved in scan_roots]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise se.SourceScanTimeout({
            "elapsed_seconds": 0.0, "files_seen": 0, "source_files": 0,
            "directories_seen": 0, "hits_seen": 0, "current_path": str(scan_root),
            "scan": "entry-classification",
        })
    for hit in se.scan_all_labeled_hits(
            ENTRY_API_PATTERNS, source_relpaths, scan_root,
            max_per_pattern=None, timeout=remaining):
        if time.monotonic() >= deadline:
            raise se.SourceScanTimeout({
                "elapsed_seconds": round(float(timeout), 3),
                "files_seen": 0, "source_files": 0,
                "directories_seen": len(scan_roots), "hits_seen": len(entries),
                "current_path": str(hit.get("file") or scan_root),
                "scan": "entry-classification",
            })
        pattern = str(hit["pattern"])
        api = pattern.strip("\\b().*")
        abs_file = scan_root.resolve() / str(hit["file"])
        for src, resolved_src in scan_roots:
            try:
                abs_file.relative_to(resolved_src)
                rel = abs_file.relative_to(src.parent.resolve()).as_posix()
            except ValueError:
                continue
            key = (api, rel, hit["line"])
            if key in seen:
                continue
            seen.add(key)
            danger_hits = _danger_hit_count(abs_file, danger_cache)
            if time.monotonic() >= deadline:
                raise se.SourceScanTimeout({
                    "elapsed_seconds": round(float(timeout), 3),
                    "files_seen": 0, "source_files": 0,
                    "directories_seen": len(scan_roots), "hits_seen": len(entries),
                    "current_path": str(abs_file), "scan": "entry-classification",
                })
            entries.append({
                "api": api,
                "input_shape": hit["label"],
                "file_line": "%s:%d" % (rel, hit["line"]),
                "default_features": "[]",
                "untrusted": True,
                "danger_hits": danger_hits,
                "module": rel.split("/")[0],
                "entry_kind": "library-api",
                "text": hit["text"],
            })
    entries.sort(key=lambda e: (str(e.get("file_line")), str(e.get("api"))))
    if time.monotonic() >= deadline:
        raise se.SourceScanTimeout({
            "elapsed_seconds": round(float(timeout), 3),
            "files_seen": 0, "source_files": 0,
            "directories_seen": len(scan_roots), "hits_seen": len(entries),
            "current_path": str(scan_root), "scan": "entry-classification-sort",
        })
    return entries


def scan_entries(source_dirs: List[Path],
                 max_items: int = 20) -> List[Dict[str, Any]]:
    """Bounded entry digest for configs/prompts.  **Not** an index."""
    return summarize_hits(scan_all_entries(source_dirs), max_items)


def prepare_target(root: Path, name: str, target_dir: Path,
                   round_budget: Optional[Dict[str, Any]] = None) -> TargetConfig:
    """Copy a new target and inventory it within the persisted round budget."""
    from ..analysis.audit_budget import budget_path, round_budget_snapshot

    target_dir = target_dir.resolve()
    dest = root / "targets" / name
    prep_started = time.monotonic()
    if round_budget:
        budget_snapshot = round_budget_snapshot(round_budget)
        remaining_round = float(budget_snapshot["remaining_seconds"])
        # The S0 setup window is tied to the original round start, so retrying
        # preparation cannot renew its 15-minute slice.
        prep_window_remaining = max(
            0.0, TARGET_PREPARATION_MAX_SECONDS -
            float(budget_snapshot["elapsed_seconds"]))
        remaining = min(remaining_round, prep_window_remaining)
    else:
        remaining = min(600.0, TARGET_PREPARATION_MAX_SECONDS)
    deadline = prep_started + remaining

    def check_budget(stage: str, current_path: Path) -> float:
        left = deadline - time.monotonic()
        if left < 1:
            raise TargetPreparationTimeout({
                "stage": stage, "current_path": str(current_path),
                "elapsed_seconds": round(time.monotonic() - prep_started, 3),
                "claim_status": "not-a-finding",
            })
        return left

    def write_status(stage: str, current_path: Path,
                     status: str = "in-progress") -> None:
        if not round_budget:
            return
        status_path = budget_path(
            root, name, int(round_budget["round"])).parent / \
            "target-preparation-status.json"
        status_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "status": status, "stage": stage,
            "current_path": str(current_path),
            "elapsed_seconds": round(time.monotonic() - prep_started, 3),
            "remaining_seconds": round(max(0.0, deadline - time.monotonic()), 3),
            "round_remaining_seconds": (
                round(float(round_budget_snapshot(round_budget)["remaining_seconds"]), 3)
                if round_budget else None),
            "claim_status": "not-a-finding",
        }
        status_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        print("[S0 prepare] %s path=%s elapsed=%.1fs remaining=%.1fs" % (
            stage, current_path, payload["elapsed_seconds"],
            payload["remaining_seconds"]))

    write_status("target-type-detection", target_dir)
    is_web = _is_web_target(
        target_dir, timeout=min(30.0, check_budget("target-type-detection", target_dir)))
    if not dest.exists():
        dest.mkdir(parents=True)
        try:
            write_status("target-copy", target_dir)
            subprocess.run(
                ["rsync", "-a", "--exclude", ".git", "--exclude", "target",
                 "--exclude", "build", "--exclude", ".gradle",
                 str(target_dir) + "/", str(dest) + "/"],
                check=True, timeout=min(600.0, check_budget("target-copy", target_dir)))
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(dest, ignore_errors=True)
            raise TargetPreparationTimeout({
                "stage": "target-copy", "current_path": str(target_dir),
                "error": "rsync exceeded the remaining audit budget",
                "claim_status": "not-a-finding",
            }) from exc
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            raise
    # Auto-copy built jars from the source tree (rsync excludes target/, so a
    # freshly built jar would otherwise never be seen by the jar scan).
    jar_srcs: List[Path] = []
    for pat in ("target/*.jar", "*/target/*.jar", "lib/*.jar", "*.jar"):
        check_budget("jar-import", target_dir)
        jar_srcs += [p for p in target_dir.glob(pat)
                     if "sources" not in p.name and "javadoc" not in p.name]
    if jar_srcs:
        lib = dest / "lib"
        lib.mkdir(parents=True, exist_ok=True)
        for jar_source in jar_srcs:
            check_budget("jar-import", jar_source)
            shutil.copy2(jar_source, lib / jar_source.name)
    if is_web:
        # Web-app layouts vary (Clojure src/, Maven src/main/java, ...):
        # prefer a top-level src/ dir, else the copy root.
        web_dirs = [d for d in dest.iterdir() if d.is_dir() and d.name == "src"]
        source_dirs = [d.relative_to(dest).as_posix() for d in web_dirs] or ["."]
        write_status("http-entry-scan", dest)
        entries = scan_all_http_entries(
            [dest / d for d in source_dirs],
            timeout=min(600.0, check_budget("http-entry-scan", dest)))
    else:
        source_dirs = sorted(
            d.relative_to(dest).as_posix()
            for d in dest.iterdir() if (d / "src" / "main" / "java").exists())
        write_status("library-entry-scan", dest)
        try:
            entries = scan_all_entries(
                [dest / d for d in source_dirs],
                timeout=min(600.0, check_budget("library-entry-scan", dest)))
        except se.SourceScanTimeout as exc:
            raise TargetPreparationTimeout({
                "stage": "library-entry-scan", "current_path": str(dest),
                "error": str(exc), "scan_progress": exc.progress,
                "claim_status": "not-a-finding",
            }) from exc
    write_status("jar-discovery", dest)
    jars: List[str] = []
    jar_dirs = [dest]
    while jar_dirs:
        current = jar_dirs.pop()
        check_budget("jar-discovery", current)
        try:
            with os.scandir(current) as children:
                for child in children:
                    check_budget("jar-discovery", Path(child.path))
                    try:
                        if child.is_dir(follow_symlinks=False):
                            jar_dirs.append(Path(child.path))
                        elif (child.name.endswith(".jar")
                              and "sources" not in child.name
                              and "javadoc" not in child.name
                              and child.is_file(follow_symlinks=True)):
                            jars.append(Path(child.path).as_posix())
                    except OSError:
                        continue
        except OSError:
            continue
    jars.sort()
    if not jars and not is_web:
        raise SystemExit(
            "no jars found under %s: build first (mvn package / ./mvnw -DskipTests package),\n"
            "then re-run; jars under target/ or lib/ are auto-copied into lib/" % dest)
    target_urls: Dict[str, str] = {}
    env_md = target_dir / "env.md"
    if env_md.exists():
        check_budget("target-metadata", env_md)
        for line in env_md.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.lower().startswith("target_url:"):
                target_urls["local"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("target_url."):
                ver, _, url = line[11:].partition(":")
                if url.strip():
                    target_urls[ver.strip()] = url.strip()
    scope_constraints = ""
    for scope_name in ("scope.md", "SECURITY-SCOPE.md", "SECURITY.md"):
        scope_file = target_dir / scope_name
        if scope_file.exists():
            check_budget("scope-metadata", scope_file)
            scope_constraints = scope_file.read_text(
                encoding="utf-8", errors="replace").strip()
            break
    cfg = {
        "name": name,
        "discovery_date": date.today().isoformat(),
        "target_type": "web-app" if is_web else "library",
        "target_urls": target_urls,
        "scope_constraints": scope_constraints,
        "upstream_repo": "",
        "runtime_lab": {},
        "jars": [{"version": "local", "path": jars[0]}] if jars else [],
        "deps": [],
        "source_dirs": source_dirs,
        "entry_points": entries,
        "candidates": [],
        "notes": "auto-generated by autonomous driver",
    }
    check_budget("config-write", dest)
    cfg_path = root / "agent" / "regression" / "configs" / (name + "-auto.json")
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    write_status("complete", dest, status="complete")
    return TargetConfig.load(cfg_path)


def _ensure_capability_inventory(ctx: "AutoCtx", *, allow_rebuild: bool = True,
                                rebuild_budget_seconds: Optional[int] = None
                                ) -> Dict[str, Any]:
    """Load valid path indices or build them after candidate-first work.

    Candidate-first rounds call with ``allow_rebuild=False`` before S2, so a
    missing or legacy inventory is reported as deferred without blocking
    configured or model-proposed candidates. After the first candidate wave,
    the caller may allow one bounded rebuild. A failed scope never falls back
    to stale rows.
    """
    from ..analysis import capability_graph as capability
    from ..analysis import coverage as cov
    from ..analysis import semantic_calls as semantic_call
    from ..analysis import semantic_controlflow as semantic_controlflow
    from ..analysis import semantic_ast as semantic_ast
    from ..analysis import semantic_transforms as semantic_transform
    from ..analysis import semantic_bindings as semantic_binding
    from ..analysis import semantic_guards as semantic_guard
    from ..analysis import semantic_paths as semantic
    from ..analysis import evidence_provenance as evidence_provenance_analysis
    from ..analysis import threat_model as threat_model_analysis
    from ..analysis.inventory import (CoverageStore, build_inventory,
                                      coverage_scope_status, persist_inventory)
    from ..analysis.languages import SourceFilter, SourceScanTimeout

    store = CoverageStore(ctx.root, ctx.cfg.name)
    target_root, _effective_source_dirs = _target_source_scope(ctx)
    # Keep the configured (rather than normalized) spellings for the persisted
    # contract so a missing/outside path remains a visible scope gap.
    source_dirs = list(ctx.cfg.source_dirs or [])
    scan_timeout = getattr(ctx.cfg, "coverage_scan_timeout_seconds", 600)
    if (isinstance(scan_timeout, bool)
            or not isinstance(scan_timeout, int) or scan_timeout < 0):
        return {"rebuilt": False,
                "error": "coverage_scan_timeout_seconds must be a nonnegative integer",
                "scope": {"status": "invalid-config", "usable": False},
                "graph": {}, "candidates": []}
    source_filter = SourceFilter(scan_timeout_seconds=scan_timeout)
    budget_reader = getattr(ctx, "round_budget_remaining", None)
    round_remaining = budget_reader() if callable(budget_reader) else None
    runtime_budget = round_remaining
    if rebuild_budget_seconds is not None:
        rebuild_budget = int(rebuild_budget_seconds)
        if rebuild_budget < 1:
            return {"rebuilt": False, "deferred": True,
                    "status": "deferred", "error": "no round budget remains",
                    "scope": {"status": "deferred", "usable": False},
                    "graph": {}, "candidates": []}
        runtime_budget = (min(runtime_budget, rebuild_budget)
                          if runtime_budget is not None else rebuild_budget)
    if runtime_budget is not None:
        source_filter.runtime_deadline_override_seconds = runtime_budget
    scope_status = coverage_scope_status(
        store, target_root, source_dirs or None,
        source_filter=source_filter, target_type=ctx.cfg.target_type)
    required_ready = (store.path(capability.CAPABILITY_GRAPH_INDEX).exists()
            and store.path(threat_model_analysis.THREAT_MODEL_INDEX).exists()
            and store.path(semantic.SEMANTIC_PATH_INDEX).exists()
            and store.path(semantic_guard.SEMANTIC_GUARD_INDEX).exists()
            and store.path(semantic_call.SEMANTIC_CALL_INDEX).exists()
            and store.path(semantic_controlflow.SEMANTIC_CONTROLFLOW_INDEX).exists()
            and store.path(semantic_ast.SEMANTIC_AST_INDEX).exists()
            and store.path(semantic_transform.SEMANTIC_TRANSFORM_INDEX).exists()
            and store.path(semantic_binding.SEMANTIC_BINDING_INDEX).exists()
            and store.path(evidence_provenance_analysis.EVIDENCE_PROVENANCE_INDEX).exists())
    # An incomplete/failed scan must never make old derived artifacts look
    # current. Permit a retry only after an explicit --force or a changed scope/
    # timeout; an unchanged failed scan would otherwise repeat every round.
    build_status = scope_status.get("build_status") or {}
    expected_scope = scope_status.get("expected") or {}
    actual_scope = scope_status.get("actual") or {}
    scope_fields = ("root", "source_dirs", "requested_source_dirs",
                    "invalid_source_dirs", "filter", "target_type")
    # Compare against this attempt, never the last successful inventory. A
    # failed rebuild after widening the scope leaves that old inventory intact.
    # Comparing to it would automatically repeat the same failed work forever.
    attempted_scope = build_status.get("attempt_scope")
    if isinstance(attempted_scope, dict):
        contract_changed = any(expected_scope.get(field) != attempted_scope.get(field)
                               for field in scope_fields)
    elif build_status.get("status") in {"running", "incomplete", "failed"}:
        # Legacy failures did not retain their contract. An unknown attempt is
        # not evidence of a changed scope; --force migrates it explicitly.
        contract_changed = False
    else:
        contract_changed = any(expected_scope.get(field) != actual_scope.get(field)
                               for field in scope_fields)
    retry_scope_changed = (contract_changed
        or ("source_dirs" in build_status and
            build_status["source_dirs"] != source_dirs)
        or ("timeout_seconds" in build_status and
            build_status["timeout_seconds"] != scan_timeout))
    attempt_key = (expected_scope.get("scope_id", ""), scan_timeout)
    attempted = getattr(ctx, "_coverage_attempted_contracts", set())
    retry_requested = bool(getattr(ctx, "force", False)) and attempt_key not in attempted
    blocked_scope = scope_status["status"] in {
        "running", "incomplete", "failed", "invalid",
    }
    if blocked_scope and not (retry_requested or retry_scope_changed):
        return {"rebuilt": False,
                "error": "coverage scope is %s; refusing stale derived indices" %
                         scope_status["status"],
                "coverage": {"state": "scope-incomplete",
                             "claim_status": "not-a-finding"},
                "scope": scope_status, "graph": {}, "candidates": []}
    scope_requires_rebuild = scope_status["status"] in {
        "missing", "legacy", "mismatch", "running", "incomplete",
        "failed", "invalid",
    }
    if required_ready and not scope_requires_rebuild:
        refresh = cov.refresh_candidate_coverage(store, ctx.root, ctx.cfg.name)
        return {"rebuilt": False, "coverage": refresh,
                "scope": scope_status,
                "graph": capability.load_capability_graph(store),
                "candidates": capability.load_capability_candidates(store),
                "semantic": semantic.load_semantic_evidence(store),
                "semantic_guards": semantic_guard.load_semantic_guards(store),
                "semantic_guard_candidates": semantic_guard.load_semantic_guard_candidates(store),
                "semantic_calls": semantic_call.load_semantic_call_evidence(store),
                "semantic_call_candidates": semantic_call.load_semantic_call_candidates(store),
                "semantic_controlflow": semantic_controlflow.load_semantic_controlflow(store),
                "semantic_controlflow_candidates": semantic_controlflow.load_semantic_controlflow_candidates(store),
                "semantic_ast": semantic_ast.load_semantic_ast(store),
                "semantic_ast_candidates": semantic_ast.load_semantic_ast_candidates(store),
                "semantic_transforms": semantic_transform.load_semantic_transform_evidence(store),
                "semantic_transform_candidates": semantic_transform.load_semantic_transform_candidates(store),
                "semantic_bindings": semantic_binding.load_semantic_binding_evidence(store),
                "semantic_binding_candidates": semantic_binding.load_semantic_binding_candidates(store),
                "evidence_provenance": evidence_provenance_analysis.load_evidence_provenance(store),
                "threat_model": threat_model_analysis.load_threat_model(
                    ctx.root, ctx.cfg.name)}

    # Autonomous S2 must be able to validate an initial candidate before a
    # potentially repository-wide rebuild. Reuse complete, matching indices
    # above, but defer new/missing/stale inventory work until there is no
    # candidate waiting for a falsifier.
    if not allow_rebuild:
        deferred_scope = dict(scope_status)
        deferred_scope["status"] = "deferred"
        deferred_scope["usable"] = False
        deferred_scope["mismatches"] = list(
            deferred_scope.get("mismatches") or []) + ["capability-index-not-ready"]
        return {"rebuilt": False, "deferred": True, "status": "deferred",
                "error": "capability inventory deferred until candidate-first work completes",
                "scope": deferred_scope, "graph": {}, "candidates": [],
                "semantic": {}, "semantic_guards": {},
                "semantic_guard_candidates": [], "semantic_calls": {},
                "semantic_call_candidates": [], "semantic_controlflow": {},
                "semantic_controlflow_candidates": [], "semantic_ast": {},
                "semantic_ast_candidates": [], "semantic_transforms": {},
                "semantic_transform_candidates": [], "semantic_bindings": {},
                "semantic_binding_candidates": [], "evidence_provenance": {},
                "threat_model": {}}

    try:
        attempted.add(attempt_key)
        ctx._coverage_attempted_contracts = attempted
        build_record = {
            "status": "running",
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "timeout_seconds": source_filter.scan_timeout_seconds,
            "runtime_budget_seconds": runtime_budget,
            "source_dirs": source_dirs,
            "attempt_scope": expected_scope,
        }
        store.write("coverage-build-status", build_record)

        def report_progress(progress: Dict[str, Any]) -> None:
            store.write("coverage-build-status", {
                **build_record, **progress, "status": "running",
            })

        result = build_inventory(target_root, source_dirs or None,
                                 source_filter=source_filter,
                                 target=ctx.cfg.name,
                                 target_type=ctx.cfg.target_type,
                                 work_budget=getattr(ctx, "work_budget", None),
                                 progress_callback=report_progress)
        persist_inventory(store, result, target_type=ctx.cfg.target_type)
        store.write("coverage-build-status", {
            **build_record,
            "status": "complete",
            "completed_at": datetime.now().isoformat(timespec="seconds"),
            "scope_id": result.scope.get("scope_id", ""),
            "source_files": len(result.files),
            "elapsed_ms": result.elapsed_ms,
        })
        refreshed_scope = coverage_scope_status(
            store, target_root, source_dirs or None,
            source_filter=source_filter, target_type=ctx.cfg.target_type)
        if not refreshed_scope.get("usable"):
            return {"rebuilt": True,
                    "error": "rebuilt coverage scope is %s; refusing derived indices" %
                             refreshed_scope.get("status", "unknown"),
                    "coverage": {"state": "scope-incomplete",
                                 "claim_status": "not-a-finding"},
                    "scope": refreshed_scope, "graph": {}, "candidates": []}
        refresh = cov.refresh_candidate_coverage(store, ctx.root, ctx.cfg.name)
        return {"rebuilt": True, "coverage": refresh,
                "scope": refreshed_scope,
                "graph": capability.load_capability_graph(store),
                "candidates": capability.load_capability_candidates(store),
                "semantic": semantic.load_semantic_evidence(store),
                "semantic_guards": semantic_guard.load_semantic_guards(store),
                "semantic_guard_candidates": semantic_guard.load_semantic_guard_candidates(store),
                "semantic_calls": semantic_call.load_semantic_call_evidence(store),
                "semantic_call_candidates": semantic_call.load_semantic_call_candidates(store),
                "semantic_controlflow": semantic_controlflow.load_semantic_controlflow(store),
                "semantic_controlflow_candidates": semantic_controlflow.load_semantic_controlflow_candidates(store),
                "semantic_ast": semantic_ast.load_semantic_ast(store),
                "semantic_ast_candidates": semantic_ast.load_semantic_ast_candidates(store),
                "semantic_transforms": semantic_transform.load_semantic_transform_evidence(store),
                "semantic_transform_candidates": semantic_transform.load_semantic_transform_candidates(store),
                "semantic_bindings": semantic_binding.load_semantic_binding_evidence(store),
                "semantic_binding_candidates": semantic_binding.load_semantic_binding_candidates(store),
                "evidence_provenance": evidence_provenance_analysis.load_evidence_provenance(store),
                "threat_model": threat_model_analysis.load_threat_model(
                    ctx.root, ctx.cfg.name),
                "root": str(target_root)}
    except SourceScanTimeout as exc:
        store.write("coverage-build-status", {
            **build_record,
            "status": "incomplete",
            "failed_at": datetime.now().isoformat(timespec="seconds"),
            "error": str(exc), "progress": exc.progress,
        })
        return {"rebuilt": False, "error": str(exc),
                "status": "incomplete", "progress": exc.progress,
                "scope": {"status": "incomplete", "usable": False},
                "graph": {}, "candidates": [],
                "claim_status": "not-a-finding"}
    except Exception as exc:  # pragma: no cover - autonomous is best-effort
        store.write("coverage-build-status", {
            **build_record,
            "status": "failed",
            "failed_at": datetime.now().isoformat(timespec="seconds"),
            "error": "%s: %s" % (type(exc).__name__, exc),
        })
        return {"rebuilt": False,
                "error": "%s: %s" % (type(exc).__name__, exc),
                "status": "failed",
                "scope": {"status": "failed", "usable": False},
                "graph": {}, "candidates": [], "semantic": {},
                "semantic_guards": {},
                "semantic_guard_candidates": [],
                "semantic_calls": {},
                "semantic_call_candidates": [],
                "semantic_controlflow": {},
                "semantic_controlflow_candidates": [],
                "semantic_ast": {},
                "semantic_ast_candidates": [],
                "semantic_transforms": {},
                "semantic_transform_candidates": [],
                "semantic_bindings": {},
                "semantic_binding_candidates": [],
                "evidence_provenance": {},
                "threat_model": {}}


