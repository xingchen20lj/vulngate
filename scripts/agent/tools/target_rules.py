"""Target-type-specific S1 patterns and conservative chain hints."""

from __future__ import annotations

from typing import Dict, List, Tuple

from .source_evidence import grep_hits


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
}


def patterns_for(target_type: str) -> List[Tuple[str, str]]:
    return TARGET_RULES.get(str(target_type), TARGET_RULES["library"])


def collect_target_rule_hits(target_type: str, source_dirs: List[str], root,
                             max_lines: int = 8) -> List[Dict]:
    hits = []
    for pattern, label in patterns_for(target_type):
        for item in grep_hits(pattern, source_dirs, root, max_lines=max_lines):
            hits.append({"label": label, "pattern": pattern, **item})
    return hits


def composite_chain_hints(graph: List[Dict], max_items: int = 80) -> List[Dict]:
    """Select paths containing both an authorization boundary and a sink."""
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
