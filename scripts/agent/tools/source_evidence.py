"""Source-evidence extraction for LLM prompts (baseline fix #3).

Deterministic, token-bounded extraction of *real* source snippets so the LLM
proposes and audits candidates from actual code, not entry names + file paths.

Two entry points:
  * surface_block(...)   -- S1.5/S2: danger-pattern call-site digest + hot
                            entry-class headers
  * candidate_block(...) -- S3/S4: snippets located from candidate entry API
                            and keywords (file + method anchored)

The same DANGER_PATTERNS list is reused by S1 for the attack-surface scan, so
the LLM prompt evidence and the deterministic scan stay in sync.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# (regex, label) pairs. Used both for the S1 danger-call-site scan and for
# locating candidate-relevant snippets. Keep patterns rg/Rust-regex safe.
DANGER_PATTERNS: List[Tuple[str, str]] = [
    (r"checkAutoType|SupportAutoType|autoType|auto_type", "autotype"),
    (r"Class\.forName|loadClass\(|ClassLoader", "dynamic-class-load"),
    (r"URLClassLoader|JarURLConnection|new\s+URL\(", "remote-resource"),
    (r"lookup\(|InitialContext|Jndi|JNDI", "jndi"),
    (r"readObject|parseObject|readValue|fromJson|fromXML|unmarshal|decodeObject",
     "deserialization-entry"),
    (r"@type|seeAlso|JsonTypeInfo|TypeInfo", "polymorphic-type"),
    (r"readLength|readString|maxDepth|maxLevel|hugeLength|\blimit\b", "bounds-limit"),
    (r"Runtime\.getRuntime|ProcessBuilder|\bexec\s*\(", "command-exec"),
    (r"getDeclaredMethod|getDeclaredField|setAccessible|\.invoke\s*\(", "reflection"),
    (r"getResourceAsStream|getResource\s*\(", "resource-load"),
]

SOURCE_MAP_PRESETS: Dict[str, str] = {
    "parsers": r"(parse\w*|read\w*|deserialize\w*|decode\w*|load\w*|convert\w*)\s*\(",
    # Language-agnostic route surface: Java servlet/Spring, Clojure compojure
    # (defendpoint/defroutes appear as `(api.macros/defendpoint :get "/x" ...)`
    # so they are matched as bare words, not call forms), Python Flask,
    # Go net/http, JS Express/Fastify. Flask/Flask-AppBuilder:
    # @bp.route("/x"), @expose("/x"), @app.get(...), app.add_url_rule(...).
    # `@`-prefixed decorators must not be anchored by \b (non-word char).
    "http": r"(?:@[\w.]+\.route|@expose|@[\w.]+\.(?:get|post|put|delete|patch))\s*\(|\b(?:doGet|doPost|service|handleRequest|onRequest|DispatcherServlet|Controller|RequestMapping|router\.(?:GET|POST|PUT|DELETE|PATCH|ANY)|app\.(?:get|post|put|delete|patch)|http\.HandleFunc|HandleFunc|add_route|add_url_rule)\s*\(|(?:^|[^-\w])(?:defendpoint|defroutes|defroute|compojure)\b",
    "expression": r"(evaluate|eval|invoke|getValue|template|render|lookup|format)\s*\(",
    "io": r"(read\w*|write\w*|copy\w*|unzip|extract\w*|download\w*|openConnection|getInputStream|getOutputStream)\s*\(",
    "exec": r"(Runtime|ProcessBuilder|exec\w*|CommandLine|startProcess)\s*\(",
    "config": r"(load\w*|parse\w*|readConfig|getProperty|Properties|Yaml|Xml)\s*\(",
    "all": r"(parse\w*|read\w*|deserialize\w*|decode\w*|load\w*|convert\w*|doGet|doPost|service|evaluate|eval|invoke|lookup|format|exec\w*|openConnection|getInputStream)\s*\(",
}

MAX_FILE_BYTES = 1024 * 1024

# Language-agnostic source scan. Java-only globs made S1 miss Clojure/Go/Python
# route declarations (Metabase lesson, 2026-08-10): the host fell back to manual
# rg sweeps because source-map returned nothing for .clj targets.
DEFAULT_SOURCE_GLOBS: List[str] = [
    "*.java", "*.kt", "*.scala",
    "*.clj", "*.cljc", "*.cljs",
    "*.py", "*.go", "*.rb",
    "*.js", "*.jsx", "*.ts", "*.tsx",
    "*.php", "*.rs", "*.cs", "*.c", "*.cpp", "*.h",
]

_FLOW_PATTERNS = {
    "source": re.compile(
        r"(?:request|query|param|header|body|input|payload|argv|env|config|read|load|parse|decode)", re.I),
    "transform": re.compile(
        r"(?:parse|decode|deserialize|unmarshal|convert|normalize|resolve|interpolat|template|eval)", re.I),
    "validation": re.compile(
        r"(?:validat|sanitize|allow.?list|deny.?list|check|bound|limit|schema|isValid)", re.I),
    "authorization": re.compile(
        r"(?:auth|permission|role|tenant|owner|access|privilege)", re.I),
    "sink": re.compile(
        r"(?:Runtime\.getRuntime|ProcessBuilder|\.exec\s*\(|Class\.forName|loadClass|"
        r"InitialContext|Jndi|File(?:Output|Input)Stream|openConnection|execute(?:Query|Update)?|"
        r"write(?:Bytes|Object)?\s*\(|render\s*\()", re.I),
}

_CLASS_DECL = re.compile(
    r"^(public\s+|protected\s+|private\s+)?(final\s+|abstract\s+|sealed\s+)?"
    r"(class|interface|enum|record)\s+\w+")
_METHOD_LIKE = re.compile(
    r"^\s*(public|protected|private|static|final|synchronized|native|abstract|"
    r"default|@Override|@SuppressWarnings)[^\n]*\(")


def _safe_resolve(root: Path, rel: str) -> Optional[Path]:
    root = root.resolve()
    p = (root / str(rel)).resolve()
    if str(p) == str(root) or str(p).startswith(str(root) + "/"):
        return p
    return None


def _read_lines(path: Path) -> Optional[List[str]]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def grep_hits(pattern: str, source_dirs: List[str], root: Path,
              max_lines: int = 12,
              globs: Optional[List[str]] = None) -> List[Dict[str, object]]:
    """rg a regex across source dirs; return [{file, line, text}] (relative)."""
    from . import search as srch
    globs = globs or DEFAULT_SOURCE_GLOBS
    hits: List[Dict[str, object]] = []
    for sd in source_dirs:
        d = _safe_resolve(root, sd)
        if not d or not d.exists():
            continue
        for line in srch.rg(pattern, d, globs=globs, max_count=max_lines):
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            try:
                rel = str(Path(parts[0]).resolve().relative_to(root.resolve()))
            except ValueError:
                continue
            hits.append({"file": rel, "line": int(parts[1]), "text": parts[2][:160]})
    return hits[:max_lines]


def _method_start(lines: List[str], anchor_idx: int, max_back: int = 14) -> int:
    """Walk back from an anchor line to a plausible method signature line."""
    for i in range(anchor_idx, max(-1, anchor_idx - max_back), -1):
        t = lines[i].strip()
        if _METHOD_LIKE.match(t):
            return i
        if "(" in t and ")" in t and (t.endswith("{") or t.endswith(")") or "throws" in t):
            return i
    return max(0, anchor_idx - 8)


def extract_method(path: Path, anchor_line: int, max_chars: int = 1600) -> Optional[str]:
    lines = _read_lines(path)
    if not lines or anchor_line < 1 or anchor_line > len(lines):
        return None
    start = _method_start(lines, anchor_line - 1)
    # capture signature + body until brace balance closes (depth==0) or cap.
    out_lines: List[str] = []
    depth = 0
    started = False
    for ln in lines[start:]:
        out_lines.append(ln)
        started = started or "{" in ln
        depth += ln.count("{") - ln.count("}")
        if started and depth <= 0 and len(out_lines) > 1:
            break
        if len("\n".join(out_lines)) > max_chars:
            out_lines.append("// ... (truncated)")
            break
    s = "\n".join(out_lines)
    if len(s) > max_chars:
        s = s[:max_chars] + "\n// ... (truncated)"
    return s


def extract_class_header(path: Path, max_chars: int = 1200) -> Optional[str]:
    lines = _read_lines(path)
    if not lines:
        return None
    out: List[str] = []
    for ln in lines[:80]:
        out.append(ln)
        if _CLASS_DECL.match(ln.strip()):
            break
    s = "\n".join(out)
    if len(s) > max_chars:
        s = s[:max_chars] + "\n// ... (truncated)"
    return s


def build_source_sink_graph(source_dirs: List[str], root: Path,
                            max_paths: int = 160) -> List[Dict[str, object]]:
    """Build bounded heuristic paths; every edge remains manual-review only."""
    paths: List[Dict[str, object]] = []
    root = root.resolve()
    for source_dir in source_dirs:
        directory = _safe_resolve(root, source_dir)
        if not directory or not directory.exists():
            continue
        for path in sorted(p for p in directory.rglob("*")
                           if p.is_file() and p.suffix in {".java", ".kt", ".scala", ".clj", ".py", ".go", ".js", ".ts", ".rb", ".php", ".rs", ".c", ".cpp"}):
            lines = _read_lines(path)
            if not lines:
                continue
            hits = {kind: [] for kind in _FLOW_PATTERNS}
            for number, text in enumerate(lines, 1):
                for kind, pattern in _FLOW_PATTERNS.items():
                    if pattern.search(text):
                        hits[kind].append((number, text.strip()[:200]))
            for source in hits["source"]:
                sink = next((item for item in hits["sink"]
                             if item[0] >= source[0] and item[0] - source[0] <= 160), None)
                if not sink:
                    continue
                transforms = [item for item in hits["transform"]
                              if source[0] <= item[0] <= sink[0]][:4]
                validations = [item for item in hits["validation"]
                               if source[0] <= item[0] <= sink[0]][:3]
                authorizations = [item for item in hits["authorization"]
                                  if source[0] <= item[0] <= sink[0]][:3]
                rel = str(path.relative_to(root))
                paths.append({
                    "source": "%s:%d %s" % (rel, source[0], source[1]),
                    "transform": ["%s:%d %s" % (rel, n, text) for n, text in transforms],
                    "validation": ["%s:%d %s" % (rel, n, text) for n, text in validations],
                    "authorization": ["%s:%d %s" % (rel, n, text) for n, text in authorizations],
                    "sink": "%s:%d %s" % (rel, sink[0], sink[1]),
                    "confidence": "heuristic-nearby",
                    "requires_manual_dataflow": True,
                })
                if len(paths) >= max_paths:
                    return paths
    return paths


def match_source_sink_paths(graph: List[Dict[str, object]], candidate: Dict[str, object],
                            max_paths: int = 8) -> List[Dict[str, object]]:
    """Select paths near candidate evidence without upgrading their confidence."""
    needles = [str(candidate.get("entry", ""))]
    needles += [str(x).split(":", 1)[0] for x in (candidate.get("code_location") or [])]
    needles = [x for x in needles if x]
    if not needles:
        return []
    selected = []
    for path in graph:
        blob = " ".join(str(path.get(key, "")) for key in ("source", "transform", "validation", "authorization", "sink"))
        if any(needle in blob for needle in needles):
            selected.append(path)
        if len(selected) >= max_paths:
            break
    return selected


def _budget_trim(parts: List[str], budget: int) -> List[str]:
    kept: List[str] = []
    used = 0
    for p in parts:
        if used + len(p) > budget:
            break
        kept.append(p)
        used += len(p)
    return kept


def surface_block(entries: List[Dict[str, object]], source_dirs: List[str],
                  root: Path, max_chars: int = 6000) -> str:
    """S1.5/S2: danger call-site digest + headers of hot entry classes."""
    parts: List[str] = []
    digs = []
    for pat, label in DANGER_PATTERNS:
        hits = grep_hits(pat, source_dirs, root, max_lines=4)
        if hits:
            first = hits[0]
            digs.append("%s: %d hits; e.g. %s:%s" % (
                label, len(hits), first["file"], first["line"]))
    if digs:
        parts.append("## 危险模式命中摘要（源码证据）\n" + "\n".join("- " + d for d in digs))

    seen = set()
    for ep in (entries or [])[:6]:
        fl = ep.get("file_line") or ep.get("file")
        if not fl or fl in seen:
            continue
        seen.add(fl)
        p = _safe_resolve(root, str(fl))
        if not p or not p.exists():
            continue
        hdr = extract_class_header(p, max_chars=1200)
        if hdr:
            parts.append("### %s\n```java\n%s\n```" % (fl, hdr))
    return "\n\n".join(_budget_trim(parts, max_chars)) or ""


def candidate_block(candidate: Dict[str, object], entries: List[Dict[str, object]],
                    source_dirs: List[str], root: Path,
                    max_chars: int = 6000) -> str:
    """S3/S4: snippets anchored at the candidate's entry API and keywords."""
    parts: List[str] = []
    anchors: List[Tuple[str, Optional[int]]] = []

    entry_api = str(candidate.get("entry") or "").strip("\\b().*")
    for ep in (entries or []):
        api = str(ep.get("api") or "").strip("\\b().*")
        if api and entry_api and api == entry_api:
            fl = ep.get("file_line") or ep.get("file")
            if fl:
                anchors.append((str(fl), None))
            break

    keywords = list(candidate.get("novelty_keywords") or [])
    logic = "%s %s" % (candidate.get("logic") or "", candidate.get("surface") or "")
    stop = {"public", "class", "static", "void", "json", "string", "object",
            "value", "input", "type", "parse", "using", "with", "from", "into",
            "result", "calls", "method", "when", "this", "return", "new"}
    for m in re.findall(r"[A-Za-z_][A-Za-z0-9_]{4,}", logic):
        if m.lower() not in stop:
            keywords.append(m)

    seen_kw = set()
    for kw in keywords[:6]:
        if kw in seen_kw:
            continue
        seen_kw.add(kw)
        for h in grep_hits(re.escape(kw), source_dirs, root, max_lines=2):
            anchors.append((str(h["file"]), int(h["line"])))

    seen_files = set()
    for rel, line in anchors:
        if rel in seen_files:
            continue
        seen_files.add(rel)
        p = _safe_resolve(root, rel)
        if not p or not p.exists():
            continue
        body = (extract_method(p, line, max_chars=1600) if line
                else extract_class_header(p, max_chars=1200))
        if body:
            parts.append("### %s:%s\n```java\n%s\n```" % (rel, line or "1", body))
    return "\n\n".join(_budget_trim(parts, max_chars)) or ""
