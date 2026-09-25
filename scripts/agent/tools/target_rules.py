"""Target-type-specific S1 patterns and conservative chain hints.

Scan/present split (spec §6.1): ``scan_all_target_rule_hits`` is uncapped and is
what an index builder must call; ``collect_target_rule_hits`` is the bounded
prompt digest retained for the existing S1 call site.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .source_evidence import scan_all_labeled_hits


TARGET_RULES: Dict[str, List[Tuple[str, str]]] = {
    "library": [(r"parseObject|readValue|decode|convert", "parser-entry"),
                 (r"checkAutoType|ClassLoader|readObject", "type-boundary")],
    "web-app": [(r"@(?:RequestMapping|GetMapping|PostMapping)|doGet|doPost|service", "http-entry"),
                (r"authorizeHttpRequests|hasRole|hasAuthority|Permission|tenant|owner", "authz-boundary"),
                (r"MultipartFile|upload|import|export|restore|backup", "file-workflow"),
                (r"RestTemplate|WebClient|openConnection|HttpClient", "ssrf-egress")],
    "middleware": [(r"doGet|doPost|service|handle|decode|ChannelInboundHandler", "protocol-entry"),
                    (r"ObjectInputStream|readObject|deserialize|ClassLoader", "deserialization"),
                    (r"File|Path|openConnection|ProcessBuilder|Runtime", "dangerous-sink")],
    "message-rpc": [(r"decode|deserialize|Invocation|GenericService|Metadata|Registry", "rpc-entry"),
                    (r"Hessian|Kryo|ObjectInputStream|ClassLoader", "serializer-boundary"),
                    (r"timeout|limit|maxLength|frame|buffer", "resource-boundary")],
    "logging": [(r"format|layout|pattern|lookup|message", "log-format-entry"),
                (r"Jndi|JNDI|lookup|interpolat|template", "lookup-boundary")],
    "expression": [(r"evaluate|parseExpression|eval|template|render", "expression-entry"),
                   (r"ClassLoader|Runtime|ProcessBuilder|MethodHandle", "execution-sink")],
    # [vulngate-macos-universal] macOS 原生应用（.app / Mach-O / Swift / ObjC）
    "native-app": [
        (r"application:openURL|applicationDidFinishLaunching|handleGetURLEvent"
         r"|openURL|handleOpenURL|NSApplicationMain", "ui-entry"),
        (r"NSXPCConnection|xpc_connection_create|mach_msg|bootstrap_look_up"
         r"|shouldAcceptNewConnection|CFMessagePort", "ipc-entry"),
        (r"WKWebView|evaluateJavaScript|addScriptMessageHandler"
         r"|userContentController|JSContext", "webview-boundary"),
        (r"NSKeyedUnarchiver|unarchive[A-Za-z]*|propertyListWithData"
         r"|CFPropertyListCreate|initWithCoder", "deserialization"),
        (r"posix_spawn|NSTask|execve|system\s*\(|popen\s*\(|NSAppleScript", "command-exec"),
        (r"SecItem[A-Za-z]*|SecKeychain|keychain|credential", "credential-boundary"),
        (r"AuthorizationExecuteWithPrivileges|SMJobBless|setuid|setgid"
         r"|get-task-allow|disable-library-validation", "privilege-boundary"),
        (r"fopen|NSFileManager|open\s*\(|unlink|remove|chmod", "dangerous-sink"),
    ],
}


def patterns_for(target_type: str) -> List[Tuple[str, str]]:
    return TARGET_RULES.get(str(target_type), TARGET_RULES["library"])


def scan_s1_source_rules(target_type: str, source_dirs: List[str], root,
                         danger_limit: int = 8, target_limit: int = 8,
                         timeout: Optional[float] = 600
                         ) -> Tuple[List[Dict], List[Dict]]:
    """Collect danger and target-rule digests in one bounded source scan."""
    from .source_evidence import DANGER_PATTERNS

    target_patterns = patterns_for(target_type)
    danger_keys = set(DANGER_PATTERNS)
    target_keys = set(target_patterns)
    limits = [value for value in (danger_limit, target_limit) if value >= 0]
    scan_limit = max(limits) if limits else None
    hits = scan_all_labeled_hits(
        DANGER_PATTERNS + target_patterns, source_dirs, root,
        max_per_pattern=scan_limit, timeout=timeout)
    danger_hits: List[Dict] = []
    target_hits: List[Dict] = []
    danger_counts: Dict[Tuple[str, str], int] = {}
    target_counts: Dict[Tuple[str, str], int] = {}
    for hit in hits:
        key = (str(hit.get("pattern") or ""), str(hit.get("label") or ""))
        if key in danger_keys:
            count = danger_counts.get(key, 0)
            if danger_limit < 0 or count < danger_limit:
                danger_hits.append(hit)
                danger_counts[key] = count + 1
        if key in target_keys:
            count = target_counts.get(key, 0)
            if target_limit < 0 or count < target_limit:
                target_hits.append(hit)
                target_counts[key] = count + 1
    return danger_hits, target_hits


def scan_all_target_rule_hits(target_type: str, source_dirs: List[str], root,
                              timeout: Optional[float] = 600) -> List[Dict]:
    """**Full** scan of the target-type rule set.  No cap (spec §6.1)."""
    hits = scan_all_labeled_hits(patterns_for(target_type), source_dirs, root,
                                 timeout=timeout)
    return sorted(hits, key=lambda h: (str(h["file"]), int(h["line"]),
                                       h["label"]))


def collect_target_rule_hits(target_type: str, source_dirs: List[str], root,
                             max_lines: int = 8,
                             timeout: Optional[float] = 600) -> List[Dict]:
    """Bounded digest for **prompt/report display only** (spec §2.1)."""
    return scan_all_labeled_hits(
        patterns_for(target_type), source_dirs, root,
        max_per_pattern=max_lines, timeout=timeout)


def composite_chain_hints(graph: List[Dict], max_items: int = 80) -> List[Dict]:
    """Select paths containing both an authorization boundary and a sink.

    Bounded by design -- a prompt digest.  The uncapped path set is
    ``source_evidence.scan_all_source_sink_paths`` / the PR2 flow index.
    """
    out = []
    for path in graph:
        if not path.get("authorization") or not path.get("sink"):
            continue
        out.append({
            "source": path.get("source"),
            "transform": path.get("transform", []),
            "authorization": path.get("authorization", []),
            "sink": path.get("sink"),
            "reason": "需验证授权检查是否覆盖变换后的对象/参数，以及拒绝路径是否可绕过",
            "confidence": "heuristic-nearby",
            "requires_manual_dataflow": True,
        })
        if len(out) >= max_items:
            break
    return out
