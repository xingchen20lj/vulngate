"""Directed deterministic fuzzing engine (long-term plan 2.1).

Structured mutation of parse-library inputs -- JSONB binary bytes and JSON
text -- driven by the WP-B experience templates:

  * length amplification   (container byte + length encoding + huge claim)
  * deep nesting           (fixed-array chains, nested objects)
  * type-byte sweep        (every leading byte with minimal payloads)
  * symbol index edges     (BC_SYMBOL / BC_TYPED_ANY index boundaries)
  * BC_REFERENCE injection (reference string parsed as a path expression)
  * truncation             (every prefix cut of valid streams)
  * JSON text edges        (huge exponents, nesting, escapes, @type)

Every input is derived from a seed via splitmix64, so the same
{seed, budget, template set} reproduces exactly the same corpus. Results are
classified into buckets (ok / reject / oom / soe / crash / hang / other),
deduplicated by (entry, bucket, signature), greedily minimized (ddmin-lite),
and emitted as pipeline candidates that flow through the normal S4-S8 gates.

The engine is target-agnostic: byte-level templates are format-level, and
the only target-specific piece is a probe source configured per target
(e.g. agent/regression/fuzz/<target>/FuzzProbe.java) plus the target config
fuzzer block. Discovery runs against the newest configured jar first; the
standard matrix (all versions x SafeMode) re-verifies minimized triggers.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..orchestrator.config import TargetConfig
from ..sandbox.approval import ApprovalGate
from .build import JavaMatrixRunner, MatrixCell, POCSpec

ROOT = Path(__file__).resolve().parents[2]

MASK64 = (1 << 64) - 1

# ---- deterministic PRNG -------------------------------------------------


class SplitMix64:
    def __init__(self, seed: int):
        self.s = seed & MASK64

    def next(self) -> int:
        self.s = (self.s + 0x9E3779B97F4A7C15) & MASK64
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        return (z ^ (z >> 31)) & MASK64

    def below(self, n: int) -> int:
        return self.next() % n if n > 0 else 0

    def pick(self, seq: List[Any]) -> Any:
        return seq[self.below(len(seq))]


# ---- JSONB format constants (format-level, not library-specific) -------

# signed byte constants -> unsigned hex, as used by JSONB binary format
BC_BINARY = 0x91
BC_TYPED_ANY = 0x92
BC_REFERENCE = 0x93
BC_ARRAY_FIX_0 = 0x94
BC_ARRAY_FIX_1 = 0x95
BC_ARRAY_FIX_MAX = 0xA3
BC_ARRAY = 0xA4
BC_OBJECT_END = 0xA5
BC_OBJECT = 0xA6
BC_NULL = 0xAF
BC_INT16 = 0xBC
BC_INT8 = 0xBD
BC_INT64 = 0xBE
BC_INT64_INT = 0xBF
BC_INT32 = 0x48
BC_STR_ASCII_FIX_MIN = 0x49
BC_STR_ASCII_FIX_MAX = 0x78
BC_STR_ASCII = 0x79
BC_STR_UTF8 = 0x7A
BC_STR_UTF16 = 0x7B
BC_STR_UTF16LE = 0x7C
BC_STR_UTF16BE = 0x7D
BC_STR_GB18030 = 0x7E
BC_SYMBOL = 0x7F

INTERESTING_BYTES = [
    BC_INT32, BC_STR_ASCII_FIX_MIN, BC_STR_ASCII_FIX_MAX, BC_STR_ASCII,
    BC_STR_UTF8, BC_STR_UTF16, BC_STR_UTF16LE, BC_STR_UTF16BE, BC_STR_GB18030,
    BC_SYMBOL, BC_BINARY, BC_TYPED_ANY, BC_REFERENCE,
    BC_ARRAY_FIX_0, BC_ARRAY_FIX_1, BC_ARRAY_FIX_MAX, BC_ARRAY,
    BC_OBJECT_END, BC_OBJECT, BC_NULL, BC_INT16, BC_INT8, BC_INT64,
    BC_INT64_INT, 0x90, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
    0xB0, 0xB1, 0xB7, 0xBB, 0x40, 0x44, 0x47, 0x30, 0x38, 0x2F, 0x5A,
]


def be16(n: int) -> bytes:
    return bytes([(n >> 8) & 0xFF, n & 0xFF])


def be32(n: int) -> bytes:
    return bytes([(n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def _len_enc(n: int) -> bytes:
    """Length encoding accepted by JSONB readLength(): byte/short markers
    or BC_INT32 + 4 bytes (big-endian)."""
    if -2048 <= n <= 2047:
        return bytes([0x38 + ((n >> 8) & 0x07), n & 0xFF])
    if -262144 <= n <= 262143:
        return bytes([0x44 + ((n >> 16) & 0x03), (n >> 8) & 0xFF, n & 0xFF])
    return bytes([BC_INT32]) + be32(n)


def _str_bytes(s: str) -> bytes:
    b = s.encode("utf-8", errors="surrogatepass")
    return bytes([BC_STR_UTF8]) + _len_enc(len(b)) + b


def to_hex(b: bytes) -> str:
    return b.hex()


def from_hex(h: str) -> bytes:
    return bytes.fromhex(h)


# ---- template builders --------------------------------------------------

LEN_VALUES = [
    0x10000000, 0x0FFFFFFF, 0x10000001, 0x08000000, 0x04000000,
    0x7FFFFFFF, -1, -2, -3, 0x80000000, 0x7FFFFF00, 0x00010000,
    0x00040000, 0x0003FFFF, -0x40000, 2048, 0x1000, 4096, -2048,
]
CONTAINERS = [
    BC_STR_UTF8, BC_STR_ASCII, BC_STR_UTF16, BC_STR_UTF16LE,
    BC_STR_UTF16BE, BC_STR_GB18030, BC_ARRAY, BC_BINARY,
]
TAILS = [b"", b"\xaf", b"\x41", b"\x00", b"\xa5"]


def build_jsonb_length(rng: SplitMix64, ctx: Dict[str, Any]) -> List[bytes]:
    out: List[bytes] = []
    for c in CONTAINERS:
        for v in LEN_VALUES:
            for enc in (_len_enc(v), bytes([BC_INT32]) + be32(v)):
                tail = rng.pick(TAILS)
                out.append(bytes([c]) + enc + tail)
    return out


DEPTHS = [64, 256, 512, 1024, 2000, 4000, 8000, 20000]


def build_jsonb_depth(rng: SplitMix64, ctx: Dict[str, Any]) -> List[bytes]:
    out: List[bytes] = []
    for d in DEPTHS:
        # fixed-array chain (no per-level length allocation)
        out.append(bytes([BC_ARRAY_FIX_1]) * d + bytes([BC_NULL]))
        # alternating fix-0 / fix-1
        out.append(bytes([BC_ARRAY_FIX_0 if i % 2 == 0 else BC_ARRAY_FIX_1
                          for i in range(d)]) + bytes([BC_NULL]))
        # nested objects: BC_OBJECT + name ... innermost value + BC_OBJECT_END
        if d <= 4000:
            out.append(bytes([BC_OBJECT]) + _str_bytes("a") * d
                       + bytes([BC_NULL]) + bytes([BC_OBJECT_END]) * d)
        # variable-length array with length 1 wrapping a fix-1 chain
        out.append(bytes([BC_ARRAY]) + _len_enc(1) + bytes([BC_ARRAY_FIX_1]) * min(d, 4096)
                   + bytes([BC_NULL]))
    return out


SYMBOL_PAYLOADS = [
    [BC_SYMBOL, 0x00],
    [BC_SYMBOL, BC_INT8, 0x00],
    [BC_SYMBOL, BC_INT8, 0xFF],
    [BC_SYMBOL, BC_INT16, 0x00, 0x00],
    [BC_SYMBOL, BC_INT16, 0xFF, 0xFF],
    [BC_SYMBOL, BC_INT32, 0x00, 0x00, 0x00, 0x00],
    [BC_SYMBOL, BC_INT32, 0xFF, 0xFF, 0xFF, 0xFF],
    [BC_SYMBOL, BC_INT32, 0x7F, 0xFF, 0xFF, 0xFF],
    [BC_SYMBOL, BC_INT32, 0x80, 0x00, 0x00, 0x00],
    [BC_SYMBOL, 0x40, 0x00, 0x00],
    [BC_SYMBOL, 0x47, 0xFF, 0xFF],
    [BC_SYMBOL, 0x2F],
    [BC_SYMBOL, 0x30],
    [BC_SYMBOL, 0x3F],
    [BC_TYPED_ANY, BC_SYMBOL, 0x00],
    [BC_TYPED_ANY, BC_SYMBOL, BC_INT32, 0x00, 0x00, 0x00, 0x00],
    [BC_TYPED_ANY, BC_SYMBOL, BC_INT32, 0xFF, 0xFF, 0xFF, 0xFF],
    [BC_OBJECT, BC_SYMBOL, 0x00, BC_NULL, BC_OBJECT_END],
    [BC_OBJECT, BC_SYMBOL, BC_INT32, 0xFF, 0xFF, 0xFF, 0xFF, BC_NULL, BC_OBJECT_END],
]


def build_jsonb_symbol(rng: SplitMix64, ctx: Dict[str, Any]) -> List[bytes]:
    return [bytes(p) for p in SYMBOL_PAYLOADS]


REF_PATHS = [
    "$", "$..", "$[0]", "$.a", "..", "$.a.b.c.d.e.f.g",
    "$[0:999999999]", "$.length()", "$.size()", "$.a[?(@.b=='x')]", "@",
    "$['\\']", "\\", "$.a\\", "$.a\ud800", "$.a\n", "null",
    "$.a" + ".b" * 80, "(", "$[(@.length-1)]", "$.a['x']", "$['a']['b']",
    "$..*", "$.a[0,1,2,3]", "$.a.b[?(@>1)]",
]


def build_jsonb_reference(rng: SplitMix64, ctx: Dict[str, Any]) -> List[bytes]:
    out: List[bytes] = []
    for p in REF_PATHS:
        out.append(bytes([BC_OBJECT]) + _str_bytes("a")
                   + bytes([BC_REFERENCE]) + _str_bytes(p) + bytes([BC_OBJECT_END]))
        out.append(bytes([BC_ARRAY]) + _len_enc(1)
                   + bytes([BC_REFERENCE]) + _str_bytes(p))
    return out


BASE_STREAMS = [
    bytes([BC_STR_UTF8]) + _len_enc(1) + b"A",
    bytes([BC_ARRAY]) + _len_enc(1) + bytes([BC_NULL]),
    bytes([BC_OBJECT]) + _str_bytes("a") + bytes([BC_NULL]) + bytes([BC_OBJECT_END]),
    bytes([BC_ARRAY]) + _len_enc(2) + bytes([BC_NULL, BC_NULL]),
    bytes([BC_OBJECT]) + _str_bytes("a") + bytes([BC_ARRAY]) + _len_enc(1)
    + bytes([BC_NULL]) + bytes([BC_OBJECT_END]),
]


def build_jsonb_truncate(rng: SplitMix64, ctx: Dict[str, Any]) -> List[bytes]:
    out: List[bytes] = []
    for base in BASE_STREAMS:
        for cut in range(1, len(base)):
            out.append(base[:cut])
        out.append(base[: len(base) // 2])
    return out


JSON_LENGTH_TEXTS = [
    '{"a":1e2147483647}', '[1e2147483647]', '1e2147483647', '-1e2147483647',
    '1E2147483647', '0.1e2147483647', '[0.0000000000000000000000001e2147483647]',
    '{"a":1234567890123456789012345678901234567890123456789012345678901234567890}',
    '[1.7976931348623157e309]', '[-1.7976931348623157e309]',
    '0e9999999999999999999999', '{"a":-1e-2147483647}',
    '1e2147483648', '1e-2147483648', '{"a":1E2147483647}',
]


def build_json_length(rng: SplitMix64, ctx: Dict[str, Any]) -> List[bytes]:
    return [t.encode("utf-8") for t in JSON_LENGTH_TEXTS]


JSON_DEPTHS = [256, 512, 1024, 2048, 4096]


def build_json_depth(rng: SplitMix64, ctx: Dict[str, Any]) -> List[bytes]:
    out: List[bytes] = []
    for d in JSON_DEPTHS:
        out.append(("[" * d + "]" * d).encode("utf-8"))
        out.append(('{"a":' * d + "1" + "}" * d).encode("utf-8"))
    out.append(b"[" * 4096)
    out.append(b'{"a":' * 3000 + b"1")
    return out


JSON_ESCAPE_TEXTS = [
    '"\\u0000"', '"\\ud800"', '"\\ud800\\udc00"', '"\\udc00"', '"\\uFFFE"',
    '"\\uFFFF"', '"\\\\"', '"\\x"', '"\\u"', '"\\uZZZZ"', '"\\u123"',
    '"\\\\n"', '"\\n"', '"\\u2028"', '"abc\\', '"', '"\u0000"',
    '{"a":"\\u0000"}', '{"a":"\\ud800"}', '{"a":"\\u2028"}',
]


def build_json_escape(rng: SplitMix64, ctx: Dict[str, Any]) -> List[bytes]:
    return [t.encode("utf-8", errors="surrogatepass") for t in JSON_ESCAPE_TEXTS]


def build_json_type(rng: SplitMix64, ctx: Dict[str, Any]) -> List[bytes]:
    out: List[bytes] = []
    for tn in ctx.get("type_names", []):
        out.append(
            ('{"@type":"%s","dataSourceName":"ldap://127.0.0.1:1389/x"}' % tn)
            .encode("utf-8"))
        out.append(('{"@type":"%s"}' % tn).encode("utf-8"))
    return out


TEMPLATE_BUILDERS: Dict[str, Callable[[SplitMix64, Dict[str, Any]], List[bytes]]] = {
    "jsonb-length": build_jsonb_length,
    "jsonb-depth": build_jsonb_depth,
    "jsonb-symbol": build_jsonb_symbol,
    "jsonb-reference": build_jsonb_reference,
    "jsonb-truncate": build_jsonb_truncate,
    "json-length": build_json_length,
    "json-depth": build_json_depth,
    "json-escape": build_json_escape,
    "json-type": build_json_type,
}

SUFFIXES = [
    b"\x00",
    b"\xaf",
    bytes([BC_INT32, 0x10, 0x00, 0x00, 0x00]),
    bytes([BC_STR_UTF8]) + _len_enc(1) + b"A",
    b"\xa5",
    bytes([BC_REFERENCE]) + _str_bytes("$"),
]


@dataclass
class FuzzInput:
    id: int
    group: str
    entry: str
    hex: str


def generate_inputs(seed: int, budget: int, groups: Dict[str, Dict[str, Any]],
                    type_names: List[str], jsonb_entries: List[str],
                    json_entries: List[str]) -> List[FuzzInput]:
    """Deterministic corpus generation: type-byte sweep first (interesting
    bytes first), then weighted template groups."""
    rng = SplitMix64(seed)
    inputs: List[FuzzInput] = []
    uid = 0

    sweep_cfg = groups.get("__sweep__", {})
    sweep_n = int(sweep_cfg.get("max_inputs", min(96, max(16, budget // 4))))
    sweep_n = max(0, min(sweep_n, budget // 2))
    sweep_bytes = sorted(
        range(256),
        key=lambda b: (0 if b in INTERESTING_BYTES else 1, b))
    sweep_entries = jsonb_entries or json_entries or ["json-object"]
    for b in sweep_bytes[:sweep_n]:
        for suffix in SUFFIXES[: int(sweep_cfg.get("variants", 1))]:
            payload = bytes([b]) + suffix
            uid += 1
            inputs.append(FuzzInput(uid, "sweep", rng.pick(sweep_entries), to_hex(payload)))

    remaining = budget - len(inputs)
    if remaining <= 0:
        return inputs

    weights: List[Tuple[str, int]] = []
    for gname, gcfg in groups.items():
        if gname == "__sweep__" or gname not in TEMPLATE_BUILDERS:
            continue
        w = int(gcfg.get("weight", 10))
        if w > 0:
            weights.append((gname, w))
    total_w = sum(w for _, w in weights) or 1
    counts = {g: max(1, remaining * w // total_w) for g, w in weights}

    for gname, cnt in counts.items():
        builder = TEMPLATE_BUILDERS[gname]
        payloads = builder(rng, {"type_names": type_names})
        if not payloads:
            continue
        entries = groups[gname].get("entries") or (
            jsonb_entries if gname.startswith("jsonb-") else json_entries)
        n = min(cnt, len(payloads))
        # deterministic spread sampling: cover head, middle and tail so
        # long/deep payloads (e.g. 20k-deep chains) are not starved by budget
        idxs = sorted({i * len(payloads) // n for i in range(n)} | {len(payloads) - 1})
        for i in range(n):
            uid += 1
            entry = entries[i % len(entries)] if entries else ""
            inputs.append(FuzzInput(uid, gname, entry, to_hex(payloads[idxs[i]])))
    return inputs[:budget]


# ---- probe output parsing / classification ------------------------------


def parse_probe_output(stdout: str) -> Dict[str, str]:
    obs: Dict[str, str] = {}
    frames: List[str] = []
    for line in stdout.splitlines():
        for key in ("CELL_START", "INPUT_BYTES", "HEX", "PARSED", "ERROR",
                    "ERROR_MSG", "CELL_DONE"):
            if line.startswith(key + "="):
                obs[key] = line[len(key) + 1:]
        if line.startswith("FRAME="):
            frames.append(line[len("FRAME="):])
    obs["FRAMES"] = frames
    return obs


def classify(obs: Dict[str, str], timed_out: bool) -> str:
    if timed_out:
        return "hang"
    err = _short_exc(obs.get("ERROR", ""))
    if not err:
        return "ok" if obs.get("PARSED") else "empty"
    if err == "OutOfMemoryError":
        return "oom"
    if err == "StackOverflowError":
        return "soe"
    if err in ("NegativeArraySizeException", "ArrayIndexOutOfBoundsException",
               "StringIndexOutOfBoundsException", "IndexOutOfBoundsException",
               "ClassCastException", "IllegalStateException", "NullPointerException"):
        return "crash"
    if err == "NumberFormatException" or err == "ArithmeticException":
        return "reject"
    if err in ("JSONException", "JSONSchemaValidException",
               "IllegalArgumentException", "SQLException"):
        return "reject"
    return "other"


def signature(obs: Dict[str, str]) -> str:
    frames = obs.get("FRAMES", [])
    head = "|".join(frames[:2])
    return "%s|%s" % (_short_exc(obs.get("ERROR", "")), head or "noframe")


def _short_exc(err: str) -> str:
    """java.lang.OutOfMemoryError -> OutOfMemoryError (stable dedup key)."""
    if "." in err:
        return err.rsplit(".", 1)[-1]
    return err


SEVERITY_ORDER = {"oom": 0, "soe": 1, "hang": 2, "crash": 3, "other": 4,
                  "reject": 5, "ok": 6, "empty": 7}


def _bucket_surface(entry: str, bucket: str, trig: Dict[str, Any]) -> str:
    detail = str(trig.get("error_msg") or trig.get("error") or bucket)
    if len(detail) > 120:
        detail = detail[:120]
    return "%s -> %s (%s)" % (entry, bucket, detail)


# ---- discovery + minimization -------------------------------------------


def _stage_probe(workspace: Path, cfg: TargetConfig, round_no: int,
                 probe_rel: str) -> Optional[Path]:
    probe = workspace / probe_rel
    if not probe.exists():
        return None
    src_dir = workspace / "poc" / cfg.name / ("round-%02d" % round_no) / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    dest = src_dir / "FuzzProbe.java"
    if not dest.exists():
        dest.write_text(probe.read_text(encoding="utf-8"), encoding="utf-8")
    return dest


def run_discovery(workspace: Path, cfg: TargetConfig, round_no: int,
                  budget: int, seed: int, jvm: Dict[str, str],
                  timeout_ms: int, primary_version: Optional[str] = None,
                  approval: Optional[ApprovalGate] = None) -> Dict[str, Any]:
    fz = getattr(cfg, "fuzzer", None) or {}
    probe_rel = fz.get("probe_src", "")
    if not probe_rel or not (workspace / probe_rel).exists():
        raise FileNotFoundError("fuzzer probe_src missing in config: %s" % probe_rel)
    staged = _stage_probe(workspace, cfg, round_no, probe_rel)
    if staged is None:
        raise FileNotFoundError("failed to stage probe %s" % probe_rel)

    jars_by_version = cfg.resolve_jars(workspace)
    versions = sorted(jars_by_version.keys())
    primary = primary_version or versions[-1]
    if primary not in jars_by_version:
        raise ValueError("primary_version %s not in config jars %s" % (primary, versions))

    groups = dict(fz.get("groups") or {})
    type_names = [g.get("type_names") for g in groups.values() if g.get("type_names")]
    type_names = [t for lst in type_names for t in lst]
    jsonb_entries = list(fz.get("jsonb_entries") or [])
    json_entries = list(fz.get("json_entries") or [])
    inputs = generate_inputs(seed, budget, groups, type_names,
                             jsonb_entries, json_entries)

    spec = POCSpec(
        candidate_id="FUZZ-DISCOVER",
        class_name="FuzzProbe",
        src="FuzzProbe.java",
        cells=[],
        safe_mode_jvm_prop=cfg.safe_mode_jvm_prop,
        module_opts=[], module_run_opts=[],
        jvm_default=jvm,
        entry="fuzz-probe", input_shape="binary/jsonb|text/json", logic="directed fuzz",
    )
    runner = JavaMatrixRunner(workspace, cfg.name, round_no, approval=approval)
    compiled = runner.compile(spec, primary, jars_by_version[primary])
    if compiled.returncode != 0:
        raise RuntimeError("FuzzProbe compile failed: %s"
                           % (compiled.stderr or compiled.stdout)[-1500:])
    t0 = time.monotonic()
    bucket_counts: Dict[str, int] = {}
    triggers: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    cells_run = 0
    for inp in inputs:
        if not inp.entry:
            continue
        for safe in (False, True):
            cell = MatrixCell(
                version=primary, safe_mode=safe, features=[],
                precondition="none",
                args=["--entry", inp.entry, "--hex", inp.hex],
                jvm=jvm, timeout=max(5, timeout_ms // 1000))
            result = runner.run_cell(spec, cell, jars_by_version[primary])
            cells_run += 1
            obs = parse_probe_output(result["stdout"])
            bucket = classify(obs, result["timed_out"])
            bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
            if bucket in ("oom", "soe", "hang", "crash", "other"):
                sig = signature(obs)
                key = (inp.entry, bucket, sig)
                if key not in triggers:
                    triggers[key] = {
                        "group": inp.group,
                        "entry": inp.entry,
                        "bucket": bucket,
                        "signature": sig,
                        "hex": inp.hex,
                        "input_len": len(from_hex(inp.hex)),
                        "error": obs.get("ERROR", ""),
                        "error_msg": obs.get("ERROR_MSG", ""),
                        "frames": obs.get("FRAMES", []),
                        "cell": {"version": primary, "safe": safe},
                        "jvm": jvm,
                        "duration_ms": result["duration_ms"],
                        "timed_out": result["timed_out"],
                    }
    report = {
        "engine": "directed-fuzz-2.1",
        "seed": seed,
        "budget": budget,
        "inputs_generated": len(inputs),
        "cells_run": cells_run,
        "matrix": {"primary_version": primary, "safe_states": [False, True]},
        "bucket_counts": bucket_counts,
        "trigger_count": len(triggers),
        "duration_sec": round(time.monotonic() - t0, 1),
    }
    return {"report": report, "triggers": triggers, "inputs": inputs}


def minimize_trigger(workspace: Path, cfg: TargetConfig, round_no: int,
                     trigger: Dict[str, Any], max_attempts: int,
                     approval: Optional[ApprovalGate] = None) -> Dict[str, Any]:
    """Greedy ddmin-lite: remove byte chunks while the anomaly persists."""
    probe_rel = (getattr(cfg, "fuzzer", None) or {}).get("probe_src", "")
    orig = from_hex(trigger["hex"])
    cell_info = trigger["cell"]
    expected = trigger["bucket"]
    expected_sig = trigger["signature"]

    runner = JavaMatrixRunner(workspace, cfg.name, round_no, approval=approval)
    spec = POCSpec(
        candidate_id="FUZZ-MIN",
        class_name="FuzzProbe",
        src="FuzzProbe.java",
        cells=[],
        safe_mode_jvm_prop=cfg.safe_mode_jvm_prop,
        jvm_default=trigger.get("jvm", {}),
    )

    def check(cand: bytes) -> bool:
        cell = MatrixCell(
            version=cell_info["version"], safe_mode=bool(cell_info["safe"]),
            features=[], precondition="none",
            args=["--entry", trigger["entry"], "--hex", to_hex(cand)],
            jvm=trigger.get("jvm", {}), timeout=30)
        result = runner.run_cell(spec, cell, runner_versions(cfg, workspace, cell_info["version"]))
        obs = parse_probe_output(result["stdout"])
        if classify(obs, result["timed_out"]) != expected:
            return False
        # keep the same anomaly (exception class + top frames), otherwise
        # ddmin drifts crash-family candidates to a different, simpler crash
        return signature(obs) == expected_sig

    work = bytearray(orig)
    granularity = max(1, len(work) // 2)
    attempts = 0
    while granularity >= 1 and attempts < max_attempts:
        i = 0
        changed = False
        while i < len(work) and attempts < max_attempts:
            cand = work[:i] + work[i + granularity:]
            if len(cand) == 0:
                i += granularity
                continue
            attempts += 1
            try:
                ok = check(bytes(cand))
            except Exception:
                ok = False
            if ok:
                work = cand
                changed = True
                continue
            i += granularity
        if not changed:
            granularity //= 2
        else:
            granularity = max(1, len(work) // 2)
    return {
        "hex": to_hex(bytes(work)),
        "len": len(work),
        "orig_len": len(orig),
        "attempts": attempts,
        "max_attempts": max_attempts,
    }


def runner_versions(cfg: TargetConfig, workspace: Path, version: str) -> List[Path]:
    return cfg.resolve_jars(workspace).get(version, [])


def emit_candidates(triggers: Dict[Tuple[str, str, str], Dict[str, Any]],
                    minimized: Dict[str, Dict[str, Any]],
                    jvm: Dict[str, str], probe_rel: str,
                    known_upstream: Optional[Dict[str, List[Dict[str, str]]]] = None) -> List[Dict[str, Any]]:
    ordered = sorted(triggers.values(), key=lambda t: SEVERITY_ORDER.get(t["bucket"], 9))
    cands: List[Dict[str, Any]] = []
    for idx, t in enumerate(ordered, 1):
        if t["bucket"] not in ("oom", "soe", "hang", "crash"):
            continue
        cid = "F%d" % idx
        min_info = minimized.get(t["signature"] + t["entry"], {})
        hex_str = min_info.get("hex") or t["hex"]
        default_reachable = not t["cell"]["safe"]
        tier = "0" if default_reachable else "single-feature"
        surface = _bucket_surface(t["entry"], t["bucket"], t)
        vector = ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                  if tier == "0" else "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L")
        refs = [dict(r) for r in (known_upstream or {}).get(t["bucket"], [])]
        cands.append({
            "candidate_id": cid,
            "surface": surface,
            "entry": "JSONB.parseObject / JSON.parse (fuzz probe entry %s)" % t["entry"],
            "input_shape": "binary/jsonb" if t["entry"].startswith("jsonb") else "text/json",
            "logic": "directed fuzz: %s" % t["bucket"],
            "hypothesis": "定向模糊发现 %s：输入 %d 字节（最小化 %d）触发 %s（%s）"
                          % (t["bucket"], t["input_len"],
                             min_info.get("len", t["input_len"]),
                             t.get("error") or t["bucket"], t.get("error_msg", "")[:100]),
            "precondition_tier_hint": tier,
            "preconditions": ["无（默认配置触发）"] if tier == "0"
                             else ["需确认触发入口的调用形态（默认配置下未复现）"],
            "entry_feature": "",
            "poc_class": "FuzzProbe",
            "jvm": jvm,
            "target_classes": [],
            "novelty_keywords": ["JSONB", _short_exc(t.get("error", "fuzz")),
                                 t["bucket"], "length", "nesting", "parse"],
            "cvss_vector": vector,
            "fuzz": True,
            "upstream_refs": refs,
            "fuzz_spec": {
                "probe_src": probe_rel,
                "entry": t["entry"],
                "hex": hex_str,
                "precondition": "none",
                "bucket": t["bucket"],
                "signature": t["signature"],
                "jvm": jvm,
                "primary_cell": t["cell"],
                "minimized": min_info,
                "report_ref": "state/<target>/round-NN/FUZZ/fuzz-report.json",
            },
        })
    return cands


# ---- pipeline-facing orchestration --------------------------------------


def run_fuzz_for_pipeline(workspace: Path, cfg: TargetConfig, round_no: int,
                          budget: int, seed: int, force: bool = False,
                          skip_minimize: bool = False) -> List[Dict[str, Any]]:
    """Discover + minimize + emit candidates into state/<target>/round-NN/FUZZ/.
    Reuses an existing report unless force=True; returns the candidate list
    that run_agent merges into S2."""
    fz = getattr(cfg, "fuzzer", None) or {}
    probe_rel = fz.get("probe_src", "")
    jvm = fz.get("jvm") or {"Xmx": "128m"}
    timeout_ms = int(fz.get("timeout_ms", 20000))
    budget = budget or int(fz.get("budget", 200))
    seed = seed or int(fz.get("seed", 20260808))
    fuzz_dir = workspace / "state" / cfg.name / ("round-%02d" % round_no) / "FUZZ"
    fuzz_dir.mkdir(parents=True, exist_ok=True)
    cand_file = fuzz_dir / "fuzz-candidates.json"

    if not force and cand_file.exists():
        cands = json.loads(cand_file.read_text(encoding="utf-8"))
        print("[fuzz] existing candidates loaded: %d" % len(cands))
        return cands

    approval = ApprovalGate(
        log_path=workspace / "state" / cfg.name
        / ("round-%02d" % round_no) / "approval-log.jsonl")
    t0 = time.monotonic()
    disc = run_discovery(workspace, cfg, round_no, budget, seed, jvm,
                         timeout_ms, approval=approval)
    report = disc["report"]
    triggers = disc["triggers"]
    minimized: Dict[str, Dict[str, Any]] = {}
    if not skip_minimize:
        ordered = sorted(triggers.values(), key=lambda t: SEVERITY_ORDER.get(t["bucket"], 9))
        # small triggers minimize in a handful of runs; cap deep/long ones
        small = [t for t in ordered if t["input_len"] <= 64]
        big = [t for t in ordered if t["input_len"] > 64][:8]
        for t in small + big:
            key = t["signature"] + t["entry"]
            min_info = minimize_trigger(workspace, cfg, round_no, t,
                                        max_attempts=120, approval=approval)
            minimized[key] = min_info
    cands = emit_candidates(triggers, minimized, jvm, probe_rel,
                            known_upstream=fz.get("known_upstream", {}))
    report["minimized_count"] = len(minimized)
    report["duration_sec"] = round(time.monotonic() - t0, 1)
    (fuzz_dir / "fuzz-report.json").write_text(
        json.dumps({"report": report,
                    "triggers": [dict(t) for t in triggers.values()],
                    "minimized": minimized}, indent=2, ensure_ascii=False),
        encoding="utf-8")
    cand_file.write_text(json.dumps(cands, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    _write_report_md(fuzz_dir, report, triggers, minimized)
    print("[fuzz] discovered: %d inputs, %d cells, %d triggers, %d candidates"
          % (report["inputs_generated"], report["cells_run"],
             report["trigger_count"], len(cands)))
    return cands


def _write_report_md(fuzz_dir: Path, report: Dict[str, Any],
                     triggers: Dict[Tuple[str, str, str], Dict[str, Any]],
                     minimized: Dict[str, Dict[str, Any]]) -> None:
    lines = [
        "# 定向模糊轮次报告（2.1）",
        "",
        "- seed=%d, budget=%d, inputs=%d, cells=%d" % (
            report["seed"], report["budget"],
            report["inputs_generated"], report["cells_run"]),
        "- 主版本矩阵：%s × SafeMode on/off" % report["matrix"]["primary_version"],
        "- bucket 分布：" + ", ".join("%s=%d" % (k, v)
                                       for k, v in sorted(report["bucket_counts"].items())),
        "- 触发数=%d，最小化=%d，耗时=%ss" % (
            report["trigger_count"], report.get("minimized_count", 0),
            report.get("duration_sec", 0)),
        "",
        "## 触发器（entry / bucket / signature / hex）",
        "",
        "| entry | bucket | error | frames | len | hex |",
        "|---|---|---|---|---|---|",
    ]
    for t in sorted(triggers.values(), key=lambda x: (x["entry"], x["bucket"])):
        frames = " / ".join(t.get("frames", [])[:2])
        lines.append("| %s | %s | %s | %s | %d | `%s` |" % (
            t["entry"], t["bucket"], t.get("error", ""), frames,
            t["input_len"], t["hex"][:64]))
    if minimized:
        lines += ["", "## 最小化结果", "",
                  "| 触发 | 原始长度 | 最小长度 | 尝试次数 | 最小 hex |",
                  "|---|---|---|---|---|"]
        for key, m in minimized.items():
            lines.append("| %s | %d | %d | %d | `%s` |" % (
                key[:60], m["orig_len"], m["len"], m["attempts"], m["hex"][:64]))
    (fuzz_dir / "fuzz-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---- CLI ----------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Directed deterministic fuzzer (plan 2.1)")
    ap.add_argument("--target", required=True, help="target name under targets/")
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--config", default=None,
                    help="target config path (default agent/regression/configs/<target>.json)")
    ap.add_argument("--budget", type=int, default=200, help="max inputs (default config value)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--force", action="store_true", help="re-discover even if report exists")
    ap.add_argument("--skip-minimize", action="store_true")
    ap.add_argument("--budget-only", action="store_true",
                    help="only print inputs to stdout (no JVM runs)")
    args = ap.parse_args(argv)

    cfg_path = Path(args.config) if args.config else (
        ROOT / "agent" / "regression" / "configs" / (args.target + ".json"))
    if not cfg_path.exists():
        print("config not found: %s" % cfg_path, file=sys.stderr)
        return 2
    cfg = TargetConfig.load(cfg_path)
    if args.budget_only:
        fz = getattr(cfg, "fuzzer", None) or {}
        groups = dict(fz.get("groups") or {})
        type_names = [t for g in groups.values() for t in g.get("type_names", [])]
        inputs = generate_inputs(
            args.seed or fz.get("seed", 20260808), args.budget, groups,
            type_names, list(fz.get("jsonb_entries") or []),
            list(fz.get("json_entries") or []))
        for inp in inputs:
            print("%s\t%s\t%s" % (inp.group, inp.entry, inp.hex))
        return 0

    cands = run_fuzz_for_pipeline(
        ROOT, cfg, args.round, args.budget, args.seed or 20260808,
        force=args.force, skip_minimize=args.skip_minimize)
    for c in cands:
        print("[candidate] %s %s" % (c["candidate_id"], c["surface"][:100]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
