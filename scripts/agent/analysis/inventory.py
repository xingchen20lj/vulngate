"""Full source / entry / sink / security-control inventory (spec §6, §23 Task 1-3).

This module owns the *universe* question: what exists in the target, and what
is the audit state of each thing?  It never truncates.  Anything that limits a
list here is a bug -- ``max_items`` style parameters belong to the renderers in
:mod:`agent.tools.source_evidence` and to the prompt builders.

Every catalog pattern is written to be valid in **both** Python ``re`` and the
Rust regex engine that ``rg`` uses (no lookaround, no backreferences), because
the same string is used for the ripgrep prefilter pass and the Python
attribution pass.

Storage layout follows spec §3::

    state/<target>/coverage/
    ├── source-inventory.json    symbol-index.json      call-graph.json
    ├── entry-index.json         source-index.json      sink-index.json
    ├── auth-boundary-index.json validation-index.json  security-control-index.json
    ├── flow-index.json          candidate-coverage.json
    ├── uncovered-regions.json   coverage-summary.json
    ├── control-map.json         control-candidates.json        (PR4, spec §11)
    ├── sibling-groups.json      differential-index.json        (PR4, spec §12)
    ├── differential-candidates.json
    ├── capability-graph.json    capability-candidates.json     (research paths)
    ├── threat-model.json        (attacker-path / trust-boundary research view)
    ├── research-strategy.json   (cross-artifact S2 research agenda)
    ├── research-agenda.json     (bounded active research queue)
    ├── research-agenda-outcomes.json (bounded agenda execution feedback)
    ├── research-budget.json     (outcome-adaptive finite budget policy)
    ├── research-guidance.json   (bounded next-action scheduling layer)
    └── inventory-summary.json

Files not yet produced by an implemented phase are omitted rather than written
empty, so ``coverage-summary.json`` can always state which indices it had.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..tools import search as srch
from . import capability_graph as capability_analysis
from . import controls as control_map
from . import differential as differential_analysis
from . import models
from . import threat_model as threat_model_analysis
from .callgraph import build_call_graph
from .dataflow import build_flow_index
from .languages import (JVM_LANGUAGES, ExcludedDir, SourceFilter, classify_file,
                        scan_tree, source_globs, suffix_owner_language)
from .symbols import (FILE_KIND, extract_symbols, index_security_surfaces,
                      relink_records)

# ---------------------------------------------------------------------------
# catalogs
# ---------------------------------------------------------------------------

#: ``(regex, category, severity_hint)``.  Categories follow spec §10 with
#: ``code-eval`` / ``expression-eval`` split out because their false-positive and
#: exploitation profiles differ from ``template-render``.
SINK_PATTERNS: List[Tuple[str, str, str]] = [
    # --- command execution -------------------------------------------------
    (r"Runtime\.getRuntime|ProcessBuilder|ProcessHandler|CommandLine"
     r"|subprocess\.(?:run|call|Popen|check_output|check_call)"
     r"|os\.system|os\.popen|os\.exec[lv]p?e?\b|child_process|execSync|spawnSync"
     r"|execFileSync|exec\.Command|posix_spawn|NSTask|popen\s*\(|\bsystem\s*\("
     r"|/bin/(?:ba)?sh|sh\s+-c\b|bash\s+-c\b", "command-exec", "high"),
    # --- code evaluation ---------------------------------------------------
    (r"\beval\s*\(|ScriptEngine|Nashorn|GroovyShell|GroovyClassLoader"
     r"|MethodHandles\.|Function\s*\(|new\s+Function|compile\s*\(", "code-eval", "high"),
    # --- expression / template -------------------------------------------
    (r"SpelExpressionParser|ExpressionParser|Ognl|OgnlContext|MVEL|Velocity"
     r"|FreeMarker|freemarker|Thymeleaf|Mustache|Handlebars|Jinja"
     r"|render_template_string|render_template|template\.render|\.render\s*\("
     r"|TemplateEngine|ScriptTemplate", "template-render", "high"),
    # --- SQL ---------------------------------------------------------------
    (r"createNativeQuery|createSQLQuery|createQuery\s*\(|Statement\.execute"
     r"|\.executeQuery\s*\(|\.executeUpdate\s*\(|jdbcTemplate|\$queryRawUnsafe"
     r"|\$executeRawUnsafe|rawQuery|execSQL|cursor\.execute|session\.execute"
     r"|connection\.execute|\.raw\s*\(|sequelize\.query|db\.query\s*\("
     r"|text\s*\(\s*['\"]|fmt\.Sprintf", "sql-exec", "high"),
    # --- deserialization ---------------------------------------------------
    (r"readObject\s*\(|ObjectInputStream|readUnshared|XMLDecoder|XStream"
     r"|Hessian|Kryo|unmarshal|fromXML|decodeObject|pickle\.loads?|yaml\.load\s*\("
     r"|marshal\.loads|NSKeyedUnarchiver|unarchive[A-Za-z]*|propertyListWithData"
     r"|CFPropertyListCreate|initWithCoder", "deserialization", "high"),
    # --- dynamic class loading / reflection -------------------------------
    (r"Class\.forName|loadClass\s*\(|ClassLoader|defineClass|URLClassLoader"
     r"|JarURLConnection|importlib\.import_module|__import__"
     r"|NSAddImage|NSCreateObjectFileImageFromFile|dlopen|dlsym",
     "dynamic-class-load", "high"),
    (r"getDeclaredMethod|getDeclaredField|getDeclaredConstructor|setAccessible"
     r"|getMethod\s*\(|\.invoke\s*\(|getattr\s*\(|setattr\s*\(|reflect\.",
     "reflection", "medium"),
    # --- JNDI / LDAP -------------------------------------------------------
    (r"InitialContext|Jndi|JNDI|LdapContext|DirContext|lookup\s*\(", "jndi", "high"),
    # --- XML external entity ----------------------------------------------
    (r"DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XMLReader"
     r"|DocumentBuilder|SAXReader|TransformerFactory", "xxe", "medium"),
    # --- network egress ----------------------------------------------------
    (r"openConnection|HttpURLConnection|URLConnection|RestTemplate|WebClient"
     r"|OkHttp|HttpClient|requests\.(?:get|post|put|delete)|urlopen|urllib"
     r"|axios|fetch\s*\(|http\.(?:Get|Post|NewRequest)|net\.Dial|NSURLSession",
     "network-egress", "high"),
    # --- file write / delete / read ---------------------------------------
    (r"FileOutputStream|FileWriter|Files\.write|Files\.copy|Files\.delete"
     r"|Files\.deleteIfExists|FileUtils\.write|writeAllBytes|writeString"
     r"|fwrite|fputs|fprintf|NSFileManager|os\.Create|io\.WriteString"
     r"|shutil\.(?:copy|copyfile|copyfileobj|rmtree)|os\.remove|os\.unlink"
     r"|deleteRecursively|unlink\s*\(|rmdir|remove\(\)", "file-mutation", "medium"),
    # Path handling that reveals or resolves a filesystem location.  The
    # earlier bare ``normalize\s*\(`` matched *any* method named ``normalize``
    # (a very common Java/Python helper name) and manufactured a file-read sink
    # for each one; receivers are now required so only real path APIs match.
    (r"getCanonicalPath|getCanonicalFile|getAbsolutePath|Paths\.get|Path\.of"
     r"|os\.path\.(?:join|normpath|normcase|abspath|realpath|expanduser)"
     r"|(?:\w+\.)?path\.(?:join|normalize|resolve)"
     r"|posixpath\.(?:join|normpath)"
     r"|filepath\.(?:Join|Clean|Abs)"
     r"|File\.(?:expand_path|realpath|absolute_path)"
     r"|sendFile|send_file"
     r"|readFile|readFileSync|FileInputStream|FileReader|Files\.read"
     r"|fopen\s*\(|open\s*\([^)]*['\"](?:r|rb)['\"]", "file-read", "medium"),
    # --- privilege ---------------------------------------------------------
    (r"\bsetuid\s*\(|\bsetgid\s*\(|seteuid|AuthorizationExecuteWithPrivileges"
     r"|SMJobBless|chmod\s*\(|chown\s*\(|\bsudo\b|runas"
     r"|AdjustTokenPrivileges|SeDebugPrivilege", "privilege", "high"),
    # --- credential access -------------------------------------------------
    (r"SecItemCopyMatching|SecItemAdd|SecItemDelete|SecKeychain|SecKeyRawSign"
     r"|SecKeyDecrypt|KeyStore\.getKey|getPassword\s*\(|readPassword"
     r"|PRIVATE KEY|private_key|SecretKeySpec|secrets\.(?:get|client)"
     r"|credentials\.", "credential-access", "high"),
    # --- native / IPC / webview bridges -----------------------------------
    (r"NSXPCConnection|xpc_connection_create|mach_msg|bootstrap_look_up"
     r"|CFMessagePort|shouldAcceptNewConnection", "native-ipc", "high"),
    (r"WKWebView|evaluateJavaScript|addScriptMessageHandler"
     r"|userContentController|JSContext|postMessage", "webview-bridge", "high"),
    # ``\b`` on every alternative: without it ``gets\s*\(`` matches ``targets(``
    # and ``strcpy\s*\(`` matches ``mystrcpy(`` -- false positives that then cost
    # real attention in the top of the risk ranking.
    (r"\bstrcpy\s*\(|\bstrcat\s*\(|\bsprintf\s*\(|\bgets\s*\(|\balloca\s*\(",
     "unsafe-c", "high"),
]

#: ``(regex, kind, input_shape)``.  ``framework`` is derived separately so one
#: pattern can describe several ecosystems.
ENTRY_PATTERNS: List[Tuple[str, str, str]] = [
    # --- HTTP --------------------------------------------------------------
    (r"@[\w.]+\.route|@expose|@[\w.]+\.(?:get|post|put|delete|patch)"
     r"|@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)"
     r"|doGet\s*\(|doPost\s*\(|doPut\s*\(|doDelete\s*\(|service\s*\(|handleRequest"
     r"|DispatcherServlet|router\.(?:GET|POST|PUT|DELETE|PATCH|ANY)"
     r"|app\.(?:get|post|put|delete|patch)\s*\(|http\.HandleFunc|HandleFunc"
     r"|add_url_rule|add_route|defendpoint|defroutes|defroute"
     r"|Route::(?:get|post|put|delete)|@Path\s*\(|\.route\s*\(",
     "http", "http-request"),
    # --- RPC ---------------------------------------------------------------
    (r"GenericService|Invocation\s*\(|Invoker|Dubbo|grpc|Thrift|Hessian"
     r"|ChannelInboundHandler|SimpleChannelInboundHandler|MessageToMessageDecoder"
     r"|@RpcService|@Service\s*\(.*rpc", "rpc", "rpc-payload"),
    # --- messaging ---------------------------------------------------------
    (r"@KafkaListener|KafkaConsumer|@RabbitListener|RabbitTemplate|JmsListener"
     r"|MessageListener|MQTT|consume\s*\(|onMessage\s*\(", "message", "message-payload"),
    # --- CLI / process -----------------------------------------------------
    (r"public\s+static\s+void\s+main\s*\(|def\s+main\s*\(|if\s+__name__\s*=="
     r"|func\s+main\s*\(|argparse|click\.command|cobra\.Command|clap::"
     r"|ARGV|sys\.argv|process\.argv|std::env::args", "cli", "process-argv"),
    # --- native IPC / URL scheme / webview ---------------------------------
    (r"application:openURL|handleGetURLEvent|openURL|handleOpenURL"
     r"|CFBundleURLSchemes|applicationDidFinishLaunching|NSApplicationMain",
     "url-scheme", "url-argument"),
    (r"NSXPCConnection|xpc_connection_create|shouldAcceptNewConnection"
     r"|CFMessagePort|mach_msg|bootstrap_look_up", "ipc", "ipc-message"),
    (r"WKWebView|evaluateJavaScript|addScriptMessageHandler|userContentController",
     "webview", "web-message"),
    # --- file / stream input ------------------------------------------------
    (r"MultipartFile|@RequestPart|FileItem|upload\s*\(|import\s*\("
     r"|restore\s*\(|backup\s*\(", "file-input", "file-content"),
    # --- library parse entries (library targets) ---------------------------
    (r"\breadValue\s*\(|\breadTree\s*\(|\bparseObject\s*\(|\bfromJson\s*\("
     r"|\bfromXml\s*\(|\bfromXML\s*\(|\bunmarshal\s*\(|\bdecodeObject\s*\("
     r"|\breadObject\s*\(|\bparse\s*\(", "library-api", "library-payload"),
    # --- environment / config ----------------------------------------------
    (r"System\.getenv|os\.environ|os\.Getenv|process\.env|\bgetProperty\s*\(",
     "config", "environment"),
]

#: ``(regex, category, control_type)`` (spec §11).  ``category`` matches the
#: spec vocabulary; ``control_type`` records the concrete mechanism.
CONTROL_PATTERNS: List[Tuple[str, str, str]] = [
    # --- authentication ----------------------------------------------------
    (r"authenticate\s*\(|AuthenticationManager|login\s*\(|verifyPassword"
     r"|checkPassword|bcrypt|argon2|totp|mfa|signInWith", "authentication", "authenticate"),
    # --- authorization -----------------------------------------------------
    (r"isAuthenticated|hasRole|hasAuthority|hasPermission|checkPermission"
     r"|@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|authorize"
     r"|authorizeHttpRequests|AccessDecisionManager|permissionService"
     r"|canAccess|isAllowed|authorize\s*\(", "authorization", "permission-check"),
    # --- object / tenant ownership ----------------------------------------
    (r"checkOwner|isOwner|ownerId|owner_id|belongsTo|sameOwner"
     r"|assertOwner|OwnershipCheck", "authorization", "owner-check"),
    (r"tenantId|tenant_id|getTenant|TenantContext|multi.?tenant|siteId"
     r"|organizationId|orgId|workspaceId", "authorization", "tenant-check"),
    # --- ACL / role --------------------------------------------------------
    (r"\bACL\b|aclEntry|AccessControlList|roleCheck|requireRole|hasGroup"
     r"|userGroups|grantAccess", "authorization", "acl-check"),
    # --- validation --------------------------------------------------------
    (r"@Valid\b|@Validated|validate\s*\(|validator\.|ValidationUtils"
     r"|isValid|checkNotNull|requireNonNull|assertThat|Preconditions"
     r"|schema\.validate|ajv|jsonschema|pydantic|conformsTo", "validation", "schema-validation"),
    # --- sanitization / normalization -------------------------------------
    (r"sanitize|escapeHtml|escapeSql|cleanInput|stripTags|Encoder\."
     r"|encodeForHTML|htmlspecialchars|quote\s*\(|normalize\s*\("
     r"|canonicalize|basename\s*\(|filepath\.Clean|secure_filename",
     "sanitization", "sanitize"),
    # --- allow / deny lists ------------------------------------------------
    (r"allow.?list|allowList|deny.?list|denyList|whitelist|blacklist"
     r"|allowedHosts|blockedHosts|permittedPaths|AllowedOrigins",
     "allowlist", "allowlist-check"),
    # --- bounds ------------------------------------------------------------
    (r"maxLength|max_length|maxDepth|maxLevel|maxSize|max_size|maxBytes"
     r"|limitLen|checkLength|readLength|hugeLength", "length-limit", "length-limit"),
    (r"maxDepth|depthLimit|recursionLimit|maxNesting|maxLevels",
     "depth-limit", "depth-limit"),
    (r"rateLimit|RateLimiter|throttle|leakyBucket|tokenBucket|@Throttle",
     "rate-limit", "rate-limit"),
    # --- CSRF / origin / signature ----------------------------------------
    (r"csrf|CSRF|xsrf|XSRF|SameSite", "csrf", "csrf-token"),
    (r"checkOrigin|Origin\b.*check|verifyOrigin|CorsConfiguration"
     r"|allowedOrigin|setAllowedOrigins", "origin-check", "origin-check"),
    (r"verifySignature|Signature\b.*verify|hmac|HMAC|checkMac|verifyToken"
     r"|validateJwt|verifyJwt|jws\.verify|timingSafeEqual", "signature-check", "signature-check"),
    # --- path safety -------------------------------------------------------
    (r"isPathTraversal|assertInside|ensureInside|pathAllowed|safeJoin"
     r"|isSubPath|realpath\s*\(|PathTraversal", "path-check", "path-check"),
    # --- feature flag / safe mode -----------------------------------------
    (r"[Ff]eature[Ff]lag|isEnabled\s*\(|featureEnabled|toggle"
     r"|safeMode|SafeMode|@ConditionalOnProperty|killSwitch", "feature-flag", "feature-flag"),
]

#: Catalog name -> (patterns, record builder key).
CATALOGS: Dict[str, List[Tuple[str, str, str]]] = {
    "sink": SINK_PATTERNS,
    "entry": ENTRY_PATTERNS,
    "control": CONTROL_PATTERNS,
}

#: Framework detection: ``(regex, framework)`` applied to a hit line + its file.
FRAMEWORK_HINTS: List[Tuple[str, str]] = [
    (r"@(?:Rest)?Controller|@RequestMapping|@GetMapping|@PostMapping"
     r"|SpringBootApplication|DispatcherServlet", "spring"),
    (r"javax\.servlet|jakarta\.servlet|doGet\s*\(|doPost\s*\(", "servlet"),
    (r"flask|Flask|render_template", "flask"),
    (r"django|Django|urlpatterns", "django"),
    (r"express|app\.(?:get|post|put|delete)\s*\(", "express"),
    (r"fastify|fastify\.", "fastify"),
    (r"http\.HandleFunc|net/http|gin\.|echo\.|fiber\.", "go-http"),
    (r"defendpoint|defroutes|compojure|ring\.", "compojure"),
    (r"Route::|laravel|Laravel", "laravel"),
    (r"rails|Rails|ApplicationController", "rails"),
    (r"@KafkaListener|KafkaConsumer", "kafka"),
    (r"@RabbitListener|RabbitTemplate", "rabbitmq"),
    (r"NSApplicationMain|UIKit|AppDelegate|NSViewController", "cocoa"),
    (r"WKWebView|WKScriptMessageHandler", "webkit"),
    (r"NSXPCConnection|xpc_connection_create", "xpc"),
]

#: Uncovered-region risk grading for sinks (spec §5.6).
SEVERITY_RANK: Dict[str, int] = {"high": 2, "medium": 1, "low": 0}


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------

class CoverageStore:
    """Target-scoped coverage artifact store: ``state/<target>/coverage/``.

    Target-scoped (not round-scoped) because coverage accumulates across rounds:
    round N's reviewed set is round N+1's baseline.
    """

    def __init__(self, workspace: Path, target: str):
        self.workspace = Path(workspace).resolve()
        self.target = target
        self.base = self.workspace / "state" / target / "coverage"

    def ensure(self) -> Path:
        self.base.mkdir(parents=True, exist_ok=True)
        return self.base

    def path(self, name: str) -> Path:
        return self.base / ("%s.json" % name)

    def write(self, name: str, payload: Any) -> Path:
        self.ensure()
        target = self.path(name)
        tmp = target.with_name(".%s.tmp.%d" % (target.name, __import__("os").getpid()))
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(target)
        return target

    def write_records(self, name: str, records: Iterable[Any]) -> Path:
        return self.write(name, [r.as_dict() if hasattr(r, "as_dict") else r
                                 for r in records])

    def read(self, name: str, default: Any = None) -> Any:
        path = self.path(name)
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    def read_records(self, name: str) -> List[Dict[str, Any]]:
        data = self.read(name)
        return data if isinstance(data, list) else []

    def existing_indices(self) -> List[str]:
        if not self.base.exists():
            return []
        return sorted(p.stem for p in self.base.glob("*.json"))


# ---------------------------------------------------------------------------
# source universe
# ---------------------------------------------------------------------------

@dataclass
class SourceUniverse:
    """Every *source-suffix* file in scope, each with an explicit state."""

    records: List[models.SourceFileRecord] = field(default_factory=list)
    excluded_dirs: List[ExcludedDir] = field(default_factory=list)
    #: Files outside the language table (images, markdown, lockfiles, ...).
    #: They are not "omitted from the audit": the language table *is* the scope
    #: statement (spec §6.3).  Counted so the summary can prove nothing source
    #: shaped was dropped.
    non_source_files: int = 0
    scanned_files: int = 0


def enumerate_source_universe(root: Path, source_dirs: Optional[Sequence[str]] = None,
                              source_filter: Optional[SourceFilter] = None
                              ) -> SourceUniverse:
    """Build the complete source universe with an explicit state per file.

    A source file ends up in exactly one of these states (spec §18 Phase 1
    completion condition -- ``indexed`` or a non-empty ``skip_reason``, never
    neither):

    * ``indexed`` -- production code, safe to enter every downstream index;
    * ``skip_reason`` in {``generated``, ``vendor``, ``test``, ``too-large``}.
    """
    root = Path(root).resolve()
    flt = source_filter or SourceFilter()
    files, excluded = scan_tree(root, flt, source_dirs)
    known = flt.known_suffixes()
    records: List[models.SourceFileRecord] = []
    non_source = 0

    for path, rel in files:
        suffix = path.suffix.lower()
        language = suffix_owner_language(rel)
        if suffix not in known or language is None:
            non_source += 1
            continue
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        info = classify_file(rel, path)
        reasons: List[str] = []
        if info["generated"]:
            reasons.append("generated")
        if info["vendor"]:
            reasons.append("vendor")
        if info["test"]:
            reasons.append("test")
        if flt.max_file_bytes and size > flt.max_file_bytes:
            reasons.append("too-large")
        production = not reasons
        records.append(models.SourceFileRecord(
            file=rel, language=language, size=size,
            production=production, generated=bool(info["generated"]),
            vendor=bool(info["vendor"]), test=bool(info["test"]),
            indexed=production,
            skip_reason="" if production else ",".join(reasons),
            audit_state="indexed" if production else "excluded",
        ))

    records.sort(key=lambda r: r.file)
    return SourceUniverse(records=records, excluded_dirs=excluded,
                          non_source_files=non_source, scanned_files=len(files))


# ---------------------------------------------------------------------------
# pattern scanning
# ---------------------------------------------------------------------------

@dataclass
class PatternHit:
    file: str
    line: int
    text: str
    label: str
    extra: str = ""
    #: Position of the matched pattern in the catalog it was scanned from.
    index: int = -1


def _combined_pattern(patterns: Sequence[Tuple[str, str, str]]) -> str:
    return "|".join("(?:%s)" % p[0] for p in patterns)


def _read_lines(path: Path, max_bytes: int = 4 * 1024 * 1024) -> Optional[List[str]]:
    try:
        if max_bytes and path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _exclude_globs(source_filter: SourceFilter) -> List[str]:
    """ripgrep ``-g`` negations mirroring the enumeration filter.

    ``--hidden`` is used so the ripgrep pass sees the same universe
    :func:`scan_tree` enumerates (a target may legitimately keep source in a
    dotted directory); the explicit negations keep ``.git`` and build output out
    of the scan.
    """
    return ["!**/%s/**" % name for name in source_filter.effective_excludes()]


def scan_catalog(root: Path, rel_paths: Sequence[str],
                 patterns: Sequence[Tuple[str, str, str]],
                 source_filter: Optional[SourceFilter] = None,
                 extra_args: Optional[Sequence[str]] = None,
                 scan_bases: Optional[Sequence[str]] = None) -> List[PatternHit]:
    """Full scan of ``rel_paths`` for ``patterns``.  **No result cap.**

    One ripgrep prefilter pass (combined alternation), then a Python
    attribution pass over the returned lines so a line matching three patterns
    yields three hits.  A ripgrep failure is raised, not swallowed -- a silent
    empty result here would read as "no sinks in this codebase", which is the
    exact silent omission spec §19.7 forbids.

    ``scan_bases`` narrows the ripgrep roots (defaults to the top-level
    directory of each relative path).  Passing the configured ``source_dirs``
    keeps a multi-target workspace from being scanned wholesale.
    """
    root = Path(root).resolve()
    flt = source_filter or SourceFilter()
    if not rel_paths:
        return []
    globs = source_globs(extra_suffixes=flt.extra_suffixes)
    exclude_globs = _exclude_globs(flt) + ["!**/.git/**"]
    combined = _combined_pattern(patterns)
    args = list(extra_args or []) + ["--hidden"]
    hits: List[PatternHit] = []
    seen: set = set()

    bases = sorted(set(scan_bases) if scan_bases
                   else {rel.split("/")[0] for rel in rel_paths})
    allowed = set(rel_paths)
    for base in bases:
        base_path = root / base
        if not base_path.exists():
            continue
        for raw in srch.rg_matches(combined, base_path, globs=globs,
                                   exclude_globs=exclude_globs, extra_args=args):
            rel = _relative(raw["file"], root)
            if rel is None or rel not in allowed:
                continue
            text = str(raw["text"])
            for index, (pattern, label, extra) in enumerate(patterns):
                if not re.search(pattern, text):
                    continue
                key = (rel, raw["line"], label)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(PatternHit(file=rel, line=int(raw["line"]), text=text,
                                       label=label, extra=extra, index=index))
    hits.sort(key=lambda h: (h.file, h.line, h.label))
    return hits


def _relative(path_text: str, root: Path) -> Optional[str]:
    try:
        return Path(path_text).resolve().relative_to(root).as_posix()
    except (ValueError, OSError):
        return None


def _detect_framework(text: str, rel: str) -> str:
    for pattern, framework in FRAMEWORK_HINTS:
        if re.search(pattern, text):
            return framework
    return ""


# --- lightweight symbol hint ------------------------------------------------

_JAVA_DECL = re.compile(
    r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*"
    r"(?:public|protected|private|static|final|synchronized|abstract|native|"
    r"default|sealed|non-sealed|override|inline|suspend|open|internal|"
    r"def|func|fun|function|fn|async)\b[^;=]*[\(\)][^;=]*[{:]?\s*$")
_GENERIC_DECL = re.compile(
    r"^\s*(?:def|func|fun|function|fn|sub|async\s+def)\s+([A-Za-z_][\w.]*)\s*\(")
_TYPE_DECL = re.compile(
    r"^\s*(?:public\s+|final\s+|abstract\s+|sealed\s+|static\s+)*"
    r"(?:class|interface|enum|record|struct|protocol|extension|trait|object)\s+"
    r"([A-Za-z_][\w]*)")


def _symbol_hint(lines: Sequence[str], line_no: int, rel: str,
                 look_back: int = 120) -> str:
    """Nearest enclosing declaration above ``line_no`` -- a *hint*, not a symbol.

    PR2's :mod:`agent.analysis.symbols` replaces this with a real symbol index
    and re-links the records; the hint exists so entry/sink/control records are
    usable (groupable, diffable) already in PR1.
    """
    if not lines or line_no < 1:
        return ""
    idx = min(len(lines), line_no) - 1
    for i in range(idx, max(-1, idx - look_back), -1):
        text = lines[i]
        match = _GENERIC_DECL.match(text)
        if match:
            return "%s#%s" % (rel, match.group(1).rsplit(".", 1)[-1])
        match = _TYPE_DECL.match(text)
        if match:
            return "%s#%s" % (rel, match.group(1))
        if _JAVA_DECL.match(text) and "(" in text:
            name = re.search(r"([A-Za-z_]\w*)\s*\(", text)
            if name:
                return "%s#%s" % (rel, name.group(1))
    return ""


# ---------------------------------------------------------------------------
# index builders
# ---------------------------------------------------------------------------

def build_sink_index(root: Path, production_rels: Sequence[str],
                     source_filter: Optional[SourceFilter] = None,
                     scan_bases: Optional[Sequence[str]] = None
                     ) -> List[models.SinkRecord]:
    hits = scan_catalog(root, production_rels, SINK_PATTERNS, source_filter,
                        scan_bases=scan_bases)
    line_cache: Dict[str, Optional[List[str]]] = {}
    records: List[models.SinkRecord] = []
    for hit in hits:
        if hit.file not in line_cache:
            line_cache[hit.file] = _read_lines(root / hit.file)
        lines = line_cache[hit.file] or []
        api = _api_name(hit.text, hit.label)
        records.append(models.SinkRecord(
            sink_id="sink:%s:%s:%d" % (hit.label, hit.file, hit.line),
            category=hit.label, file=hit.file, line=hit.line,
            symbol_id=_symbol_hint(lines, hit.line, hit.file),
            api=api, text=hit.text.strip()[:240],
            severity_hint=hit.extra,
            review_state="indexed",
        ))
    return records


def build_entry_index(root: Path, production_rels: Sequence[str],
                      source_filter: Optional[SourceFilter] = None,
                      target_type: Optional[str] = None,
                      scan_bases: Optional[Sequence[str]] = None
                      ) -> List[models.EntryRecord]:
    """Entry inventory: language-agnostic catalog + target-type rules.

    Target-type rule hits keep a clean ``kind`` (``target-rule``) and record the
    rule label separately in ``rule_label`` so ``kind`` stays groupable.
    """
    patterns = list(ENTRY_PATTERNS)
    rule_labels = {i: "" for i in range(len(patterns))}
    if target_type:
        # Late import: keeps ``analysis`` free of an import-time dependency on
        # the legacy tools package.
        from ..tools.target_rules import patterns_for
        for pattern, label in patterns_for(target_type):
            rule_labels[len(patterns)] = label
            patterns.append((pattern, "target-rule", "target-rule"))
    hits = scan_catalog(root, production_rels, patterns, source_filter,
                        scan_bases=scan_bases)
    line_cache: Dict[str, Optional[List[str]]] = {}
    records: List[models.EntryRecord] = []
    seen: set = set()
    for hit in hits:
        rule_label = rule_labels.get(hit.index, "")
        if hit.file not in line_cache:
            line_cache[hit.file] = _read_lines(root / hit.file)
        lines = line_cache[hit.file] or []
        symbol = _symbol_hint(lines, hit.line, hit.file)
        entry_id = "%s:%s:%s:%d" % (hit.label, rule_label or hit.extra, hit.file, hit.line)
        if entry_id in seen:
            continue
        seen.add(entry_id)
        records.append(models.EntryRecord(
            entry_id=entry_id, kind=hit.label, file=hit.file, line=hit.line,
            symbol_id=symbol,
            input_shape="target-rule" if rule_label else (hit.extra or "unknown"),
            untrusted=True, framework=_detect_framework(hit.text, hit.file),
            api=_api_name(hit.text, hit.label), target_type=target_type or "",
            rule_label=rule_label, review_state="indexed",
        ))
    return records


def build_control_index(root: Path, production_rels: Sequence[str],
                        source_filter: Optional[SourceFilter] = None,
                        scan_bases: Optional[Sequence[str]] = None
                        ) -> List[models.SecurityControlRecord]:
    hits = scan_catalog(root, production_rels, CONTROL_PATTERNS, source_filter,
                        scan_bases=scan_bases)
    line_cache: Dict[str, Optional[List[str]]] = {}
    records: List[models.SecurityControlRecord] = []
    for hit in hits:
        if hit.file not in line_cache:
            line_cache[hit.file] = _read_lines(root / hit.file)
        lines = line_cache[hit.file] or []
        records.append(models.SecurityControlRecord(
            control_id="%s:%s:%d" % (hit.label, hit.file, hit.line),
            category=hit.label, file=hit.file, line=hit.line,
            symbol_id=_symbol_hint(lines, hit.line, hit.file),
            control_type=hit.extra, api=_api_name(hit.text, hit.label),
            text=hit.text.strip()[:240], confidence="heuristic",
            review_state="indexed",
        ))
    return records


def build_auth_boundary_index(controls: Sequence[models.SecurityControlRecord],
                              ) -> List[Dict[str, Any]]:
    """Auth/authz/tenant/owner/ACL subset of the control index (spec §5.5)."""
    wanted = {"authentication", "authorization"}
    return [c.as_dict() for c in controls if c.category in wanted]


def build_validation_index(controls: Sequence[models.SecurityControlRecord],
                           ) -> List[Dict[str, Any]]:
    wanted = {"validation", "sanitization", "allowlist", "length-limit",
              "depth-limit", "path-check", "origin-check", "signature-check"}
    return [c.as_dict() for c in controls if c.category in wanted]


def _api_name(text: str, label: str) -> str:
    match = re.search(r"([A-Za-z_][\w.]{2,})\s*\(", text)
    if match:
        return match.group(1).rsplit(".", 1)[-1]
    stripped = text.strip()
    return stripped[:60] if stripped else label


# ---------------------------------------------------------------------------
# top level
# ---------------------------------------------------------------------------

@dataclass
class InventoryResult:
    root: str
    target: str
    generated_at: str
    filter: Dict[str, Any]
    files: List[models.SourceFileRecord] = field(default_factory=list)
    excluded_dirs: List[Dict[str, Any]] = field(default_factory=list)
    entries: List[models.EntryRecord] = field(default_factory=list)
    sinks: List[models.SinkRecord] = field(default_factory=list)
    controls: List[models.SecurityControlRecord] = field(default_factory=list)
    #: PR2: symbol index, heuristic call graph and the cross-procedural flows.
    symbols: List[models.SymbolRecord] = field(default_factory=list)
    call_edges: List[models.CallEdge] = field(default_factory=list)
    flows: List[models.FlowRecord] = field(default_factory=list)
    sink_reachability: List[Dict[str, Any]] = field(default_factory=list)
    #: PR4 (spec §11): per-flow control verdicts and the candidates derived from
    #: them.  Held as plain dicts -- they are persisted artifacts whose schema is
    #: owned by :mod:`agent.analysis.controls`, not a record type of this module.
    control_map: Dict[str, Any] = field(default_factory=dict)
    control_candidates: List[Dict[str, Any]] = field(default_factory=list)
    #: PR4 (spec §12): sibling groups, control differentials, candidates.
    differential: Dict[str, Any] = field(default_factory=dict)
    sibling_groups: List[Dict[str, Any]] = field(default_factory=list)
    differential_candidates: List[Dict[str, Any]] = field(default_factory=list)
    #: Bounded capability-primitive graph and its S2 research candidates.
    capability_graph: Dict[str, Any] = field(default_factory=dict)
    capability_candidates: List[Dict[str, Any]] = field(default_factory=list)
    symbol_read_failures: Dict[str, str] = field(default_factory=dict)
    callgraph_summary: Dict[str, Any] = field(default_factory=dict)
    flow_summary: Dict[str, Any] = field(default_factory=dict)
    relinked: int = 0
    #: Files outside the language table (images, markdown, lockfiles, ...).  They
    #: are not "omitted": the language table *is* the scope statement (§6.3).
    #: Counted so the summary can prove nothing source shaped was dropped.
    non_source_files: int = 0
    scanned_files: int = 0
    elapsed_ms: int = 0

    def counts(self) -> Dict[str, Any]:
        production = [f for f in self.files if f.production]
        skipped = [f for f in self.files if not f.production]
        reason_hist: Dict[str, int] = {}
        for rec in skipped:
            key = rec.skip_reason.split(":", 1)[0] or "unknown"
            reason_hist[key] = reason_hist.get(key, 0) + 1
        languages: Dict[str, int] = {}
        for rec in production:
            languages[rec.language or "unknown"] = languages.get(rec.language or "unknown", 0) + 1
        by_category: Dict[str, int] = {}
        for sink in self.sinks:
            by_category[sink.category] = by_category.get(sink.category, 0) + 1
        by_severity: Dict[str, int] = {}
        for sink in self.sinks:
            by_severity[sink.severity_hint] = by_severity.get(sink.severity_hint, 0) + 1
        entry_kinds: Dict[str, int] = {}
        for entry in self.entries:
            entry_kinds[entry.kind] = entry_kinds.get(entry.kind, 0) + 1
        control_categories: Dict[str, int] = {}
        for control in self.controls:
            control_categories[control.category] = \
                control_categories.get(control.category, 0) + 1
        symbol_kinds: Dict[str, int] = {}
        for symbol in self.symbols:
            symbol_kinds[symbol.kind] = symbol_kinds.get(symbol.kind, 0) + 1
        return {
            "files_total": len(self.files),
            "files_production": len(production),
            "files_indexed": len([f for f in production if f.indexed]),
            "files_skipped": len(skipped),
            "skip_reason_histogram": reason_hist,
            "excluded_dirs": len(self.excluded_dirs),
            "excluded_dir_file_count": sum(int(d.get("file_count", 0))
                                           for d in self.excluded_dirs),
            "non_source_files": self.non_source_files,
            "scanned_files": self.scanned_files,
            "languages": languages,
            "entries": len(self.entries),
            "entry_kinds": entry_kinds,
            "sinks": len(self.sinks),
            "sink_categories": by_category,
            "sink_severities": by_severity,
            "controls": len(self.controls),
            "control_categories": control_categories,
            "symbols": len(self.symbols),
            "symbol_kinds": symbol_kinds,
            "files_without_symbols": len([f for f in production
                                          if not f.symbols]),
            "files_module_level_only": len([f for f in production
                                            if f.symbols and not f.callables]),
            "symbol_read_failures": len(self.symbol_read_failures),
            "call_edges": len(self.call_edges),
            "flows": len(self.flows),
            "flows_high": self.flow_summary.get("high", 0),
            "flows_gapped": self.flow_summary.get("gapped", 0),
            "control_map": self.control_map.get("summary", {}),
            "control_candidates": len(self.control_candidates),
            "differential": self.differential.get("summary", {}),
            "sibling_groups": len(self.sibling_groups),
            "differential_candidates": len(self.differential_candidates),
            "capability_graph": self.capability_graph.get("summary", {}),
            "capability_candidates": len(self.capability_candidates),
            "records_relinked": self.relinked,
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "target": self.target,
            "generated_at": self.generated_at,
            "elapsed_ms": self.elapsed_ms,
            "filter": self.filter,
            "counts": self.counts(),
            "excluded_dirs": list(self.excluded_dirs),
            "files": [f.as_dict() for f in self.files],
            "entries": [e.as_dict() for e in self.entries],
            "sinks": [s.as_dict() for s in self.sinks],
            "controls": [c.as_dict() for c in self.controls],
            "symbols": [s.as_dict() for s in self.symbols],
            "call_edges": [e.as_dict() for e in self.call_edges],
            "flows": [f.as_dict() for f in self.flows],
            "callgraph_summary": self.callgraph_summary,
            "flow_summary": self.flow_summary,
            "control_map": self.control_map,
            "differential": self.differential,
            "capability_graph": self.capability_graph,
            "symbol_read_failures": dict(self.symbol_read_failures),
        }


def build_inventory(root: Path, source_dirs: Optional[Sequence[str]] = None,
                    source_filter: Optional[SourceFilter] = None,
                    target: str = "", target_type: Optional[str] = None,
                    with_flows: bool = True,
                    fix_history: Optional[Sequence[Dict[str, Any]]] = None
                    ) -> InventoryResult:
    """Full inventory: universe + entries + sinks + controls + symbols + flows.

    Never truncates.  ``with_flows=False`` skips the PR2 passes for callers that
    only need the PR1 catalogs; the default is to build everything so a later
    phase cannot accidentally read a half-populated coverage store.

    ``fix_history`` is the S1 patch-history artifact (from
    :func:`agent.tools.patch_variants.analyze_patch_history`).  It is optional
    input to the PR4 sibling diff (spec §18 Phase 4 "patch sibling diff"): an
    empty history is normal and only means the patch-evidence subclass of
    findings is absent, never that the differential failed.
    """
    started = time.time()
    root = Path(root).resolve()
    flt = source_filter or SourceFilter()
    universe = enumerate_source_universe(root, source_dirs, flt)
    files = universe.records
    production_rels = [r.file for r in files if r.production]

    bases = list(source_dirs) if source_dirs else None
    entries = build_entry_index(root, production_rels, flt, target_type,
                                scan_bases=bases)
    sinks = build_sink_index(root, production_rels, flt, scan_bases=bases)
    controls = build_control_index(root, production_rels, flt, scan_bases=bases)

    symbol_records: List[models.SymbolRecord] = []
    read_failures: Dict[str, str] = {}
    call_edges: List[models.CallEdge] = []
    flows: List[models.FlowRecord] = []
    reachability: List[Dict[str, Any]] = []
    callgraph_summary: Dict[str, Any] = {}
    flow_summary: Dict[str, Any] = {}
    relinked = 0
    cmap: Dict[str, Any] = {}
    control_candidates: List[Dict[str, Any]] = []
    diff_dict: Dict[str, Any] = {}
    sibling_groups: List[Dict[str, Any]] = []
    diff_candidates: List[Dict[str, Any]] = []
    capability_dict: Dict[str, Any] = {}
    capability_candidates: List[Dict[str, Any]] = []
    if with_flows:
        symbol_records, read_failures = extract_symbols(root, production_rels, flt)
        # Replace PR1's ``<file>#<nearest-declaration>`` hint with the real
        # innermost symbol before anything keys on it.
        relinked = relink_records(symbol_records,
                                  list(entries) + list(sinks) + list(controls))
        graph = build_call_graph(root, symbol_records, flt)
        call_edges = graph.edges
        callgraph_summary = graph.summary()
        flow_index = build_flow_index(root, symbol_records, graph, entries,
                                      sinks, controls)
        flows = flow_index.flows
        reachability = flow_index.reachability_dicts()
        flow_summary = flow_index.summary()
        index_security_surfaces(symbol_records, entries, sinks, controls)

        # --- PR4: control map (§11) + sibling differential (§12) ------------
        # Built here rather than in a separate pass so every consumer of the
        # store sees them: the prompt block, the candidate pool and the residual
        # all read the same persisted verdicts.
        control_map_result = control_map.build_control_map(entries, sinks, flows,
                                                          controls)
        cmap = control_map_result.as_dict()
        control_candidates = control_map.control_candidates(control_map_result)
        differential_result = differential_analysis.build_differential(
            entries, symbol_records, controls, sinks, call_edges,
            fix_history=fix_history or ())
        diff_dict = differential_result.as_dict()
        sibling_groups = differential_result.group_dicts()
        diff_candidates = differential_analysis.differential_candidates(
            differential_result.findings)
        capability_dict = capability_analysis.build_capability_graph(
            entries, sinks, flows, controls)
        capability_candidates = list(capability_dict.get("candidates") or [])

    entry_counts: Dict[str, int] = {}
    for entry in entries:
        entry_counts[entry.file] = entry_counts.get(entry.file, 0) + 1
    sink_counts: Dict[str, int] = {}
    for sink in sinks:
        sink_counts[sink.file] = sink_counts.get(sink.file, 0) + 1
    control_counts: Dict[str, int] = {}
    for control in controls:
        control_counts[control.file] = control_counts.get(control.file, 0) + 1
    symbol_counts: Dict[str, int] = {}
    callable_counts: Dict[str, int] = {}
    for symbol in symbol_records:
        symbol_counts[symbol.file] = symbol_counts.get(symbol.file, 0) + 1
        if symbol.kind != FILE_KIND:
            callable_counts[symbol.file] = callable_counts.get(symbol.file, 0) + 1
    for rec in files:
        rec.entries = entry_counts.get(rec.file, 0)
        rec.sinks = sink_counts.get(rec.file, 0)
        rec.controls = control_counts.get(rec.file, 0)
        rec.symbols = symbol_counts.get(rec.file, 0)
        rec.callables = callable_counts.get(rec.file, 0)

    return InventoryResult(
        root=str(root), target=target or root.name,
        generated_at=datetime.now().isoformat(timespec="seconds"),
        filter=flt.as_dict(), files=files,
        excluded_dirs=[d.as_dict() for d in universe.excluded_dirs],
        entries=entries, sinks=sinks, controls=controls,
        symbols=symbol_records, call_edges=call_edges, flows=flows,
        sink_reachability=reachability, symbol_read_failures=read_failures,
        callgraph_summary=callgraph_summary, flow_summary=flow_summary,
        control_map=cmap, control_candidates=control_candidates,
        differential=diff_dict, sibling_groups=sibling_groups,
        differential_candidates=diff_candidates,
        capability_graph=capability_dict,
        capability_candidates=capability_candidates,
        relinked=relinked,
        non_source_files=universe.non_source_files,
        scanned_files=universe.scanned_files,
        elapsed_ms=int((time.time() - started) * 1000),
    )


def persist_inventory(store: CoverageStore, result: InventoryResult,
                      target_type: Optional[str] = None) -> Dict[str, str]:
    """Write the inventory indices.  Returns ``{index name: path}``."""
    written: Dict[str, str] = {}
    written["source-inventory"] = str(store.write_records("source-inventory", result.files))
    written["entry-index"] = str(store.write_records("entry-index", result.entries))
    written["sink-index"] = str(store.write_records("sink-index", result.sinks))
    written["security-control-index"] = str(
        store.write_records("security-control-index", result.controls))
    written["auth-boundary-index"] = str(
        store.write("auth-boundary-index", build_auth_boundary_index(result.controls)))
    written["validation-index"] = str(
        store.write("validation-index", build_validation_index(result.controls)))
    written["symbol-index"] = str(
        store.write_records("symbol-index", result.symbols))
    written["call-graph"] = str(
        store.write_records("call-graph", result.call_edges))
    written["flow-index"] = str(
        store.write_records("flow-index", result.flows))
    written["sink-reachability"] = str(
        store.write("sink-reachability", result.sink_reachability))
    written["call-graph-summary"] = str(
        store.write("call-graph-summary", result.callgraph_summary))
    written["flow-summary"] = str(
        store.write("flow-summary", result.flow_summary))
    # PR4 (spec §11/§12).  Written as their own files so a PR3 reader that knows
    # nothing about controls sees the same directory it always did.  Skipped --
    # not written empty -- when ``with_flows=False``, so the presence of
    # ``control-map.json`` stays evidence that the pass actually ran.
    if result.control_map:
        written[control_map.CONTROL_MAP_INDEX] = str(
            store.write(control_map.CONTROL_MAP_INDEX, result.control_map))
    if result.control_candidates or result.control_map:
        written[control_map.CONTROL_CANDIDATE_INDEX] = str(
            store.write(control_map.CONTROL_CANDIDATE_INDEX,
                        result.control_candidates))
    if result.differential:
        written[differential_analysis.SIBLING_GROUP_INDEX] = str(
            store.write(differential_analysis.SIBLING_GROUP_INDEX,
                        result.sibling_groups))
        written[differential_analysis.DIFFERENTIAL_INDEX] = str(
            store.write(differential_analysis.DIFFERENTIAL_INDEX,
                        result.differential))
        written[differential_analysis.DIFFERENTIAL_CANDIDATE_INDEX] = str(
            store.write(differential_analysis.DIFFERENTIAL_CANDIDATE_INDEX,
                        result.differential_candidates))
    if result.capability_graph:
        written[capability_analysis.CAPABILITY_GRAPH_INDEX] = str(
            store.write(capability_analysis.CAPABILITY_GRAPH_INDEX,
                        result.capability_graph))
        written[capability_analysis.CAPABILITY_CANDIDATE_INDEX] = str(
            store.write(capability_analysis.CAPABILITY_CANDIDATE_INDEX,
                        result.capability_candidates))
    # The threat model is a deterministic join of the inventory, control map,
    # and capability graph.  Persist it beside the source ledger so the
    # scheduler and both pipeline drivers consume the same attacker-path view.
    threat_model = threat_model_analysis.build_threat_model(
        entries=result.entries, sinks=result.sinks, flows=result.flows,
        control_map=result.control_map,
        capability_graph=result.capability_graph,
        reachability=result.sink_reachability, target=result.target,
        target_type=target_type or "")
    written[threat_model_analysis.THREAT_MODEL_INDEX] = str(
        store.write(threat_model_analysis.THREAT_MODEL_INDEX, threat_model))
    written["inventory-summary"] = str(store.write("inventory-summary", {
        "root": result.root, "target": result.target,
        "generated_at": result.generated_at, "elapsed_ms": result.elapsed_ms,
        "filter": result.filter, "counts": result.counts(),
        "excluded_dirs": result.excluded_dirs,
        "target_type": target_type or "",
        "source_dirs": None,
    }))
    return written


def load_inventory(store: CoverageStore) -> Dict[str, Any]:
    """Read back the persisted indices as plain dicts (missing -> empty list)."""
    return {
        "source-inventory": store.read_records("source-inventory"),
        "entry-index": store.read_records("entry-index"),
        "sink-index": store.read_records("sink-index"),
        "security-control-index": store.read_records("security-control-index"),
        "auth-boundary-index": store.read_records("auth-boundary-index"),
        "validation-index": store.read_records("validation-index"),
        "symbol-index": store.read_records("symbol-index"),
        "call-graph": store.read_records("call-graph"),
        "flow-index": store.read_records("flow-index"),
        "sink-reachability": store.read_records("sink-reachability"),
        "candidate-coverage": store.read_records("candidate-coverage"),
        "uncovered-regions": store.read_records("uncovered-regions"),
        control_map.CONTROL_MAP_INDEX: store.read(control_map.CONTROL_MAP_INDEX) or {},
        control_map.CONTROL_CANDIDATE_INDEX: store.read_records(
            control_map.CONTROL_CANDIDATE_INDEX),
        differential_analysis.SIBLING_GROUP_INDEX: store.read_records(
            differential_analysis.SIBLING_GROUP_INDEX),
        differential_analysis.DIFFERENTIAL_INDEX: store.read(
            differential_analysis.DIFFERENTIAL_INDEX) or {},
        differential_analysis.DIFFERENTIAL_CANDIDATE_INDEX: store.read_records(
            differential_analysis.DIFFERENTIAL_CANDIDATE_INDEX),
        capability_analysis.CAPABILITY_GRAPH_INDEX: store.read(
            capability_analysis.CAPABILITY_GRAPH_INDEX) or {},
        capability_analysis.CAPABILITY_CANDIDATE_INDEX: store.read_records(
            capability_analysis.CAPABILITY_CANDIDATE_INDEX),
        threat_model_analysis.THREAT_MODEL_INDEX: threat_model_analysis.load_threat_model(
            store.workspace, store.target),
        "inventory-summary": store.read("inventory-summary") or {},
        "call-graph-summary": store.read("call-graph-summary") or {},
        "flow-summary": store.read("flow-summary") or {},
        "coverage-summary": store.read("coverage-summary") or {},
    }
