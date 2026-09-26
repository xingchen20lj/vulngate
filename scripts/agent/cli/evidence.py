"""Evidence and coordination CLI handlers."""

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.cli.analysis import _ensure_coverage_analysis


def _out(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def cmd_differential(args: argparse.Namespace) -> int:
    """Sibling / differential analysis (spec §12): where siblings disagree.

    Prints the sibling groups' basis, the control differentials found in them
    and the candidates they generate.  Patch evidence from S1's
    ``security-fix-history.json`` is folded in by default (spec §18 Phase 4
    "patch sibling diff"); ``--fix-history`` overrides it.  Offline and
    deterministic (spec §21.1).
    """
    from agent.analysis import differential as diff

    try:
        workspace, store, rebuilt, note = _ensure_coverage_analysis(
            args, (diff.DIFFERENTIAL_INDEX,), with_fix_history=True)
    except FileNotFoundError as exc:
        _out({"error": "target source root not found", "root": str(exc),
              "hint": "pass --root <src root> (with --rebuild) or run S1 first"})
        return 2

    index = diff.load_differential(store)
    candidates = diff.differential_candidates(index.findings, limit=args.limit_candidates)
    payload: Dict[str, Any] = {
        "target": args.target, "workspace": str(workspace),
        "summary": index.summary(),
        "findings": [f.as_dict() for f in index.findings[:max(0, args.limit)]],
        "candidates": candidates,
    }
    if note:
        payload["fix_history_note"] = note
    if rebuilt is not None:
        payload["rebuilt"] = rebuilt
    if args.json:
        _out(payload)
        return 0

    print(diff.render_differential_text(index, args.lang, limit=args.limit,
                                        candidates=candidates
                                        if args.show_candidates else None))
    if note:
        print("\n[%s]" % note)
    if rebuilt is not None:
        print("[index rebuilt from %s]" % rebuilt["root"])
    return 0


def _filter_regions(regions: List[Dict[str, Any]],
                    args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Apply ``--risk`` / ``--category`` / ``--module`` to the gap list."""
    out = list(regions)
    if args.risk:
        out = [r for r in out if str(r.get("risk")) == args.risk]
    if args.category:
        needle = args.category.lower()

        def matches(region: Dict[str, Any]) -> bool:
            detail = region.get("detail") or {}
            haystack = [str(region.get("kind", "")), str(region.get("reason", ""))]
            haystack += [str(v) for v in detail.values()]
            return any(needle in item.lower() for item in haystack)

        out = [r for r in out if matches(r)]
    if args.module:
        prefix = args.module.strip("/")
        out = [r for r in out if str(r.get("file", "")).startswith(prefix)
               or ("/" + prefix) in str(r.get("file", ""))]
    return out


def cmd_spawn_probe(args: argparse.Namespace) -> int:
    """Prepare or verify a challenge-bound S4 spawn preflight probe.

    A host-created heartbeat file or a generic greeting cannot establish that
    a spawned agent received the task.  ``--prepare`` therefore creates a
    fresh, nonce-named heartbeat target and an exact reply challenge.  A later
    ``--status ok`` succeeds only when both artifacts carry that nonce; an
    invalid success request is downgraded to sequential mode and exits nonzero.
    """
    from datetime import datetime
    from agent.memory.state import CheckpointStore

    store = CheckpointStore(Path(args.workspace), args.target, args.round)
    if getattr(args, "prepare", False):
        token = str(getattr(args, "token", "") or secrets.token_urlsafe(18))
        token = re.sub(r"[^A-Za-z0-9_-]", "", token)[:96]
        if len(token) < 12:
            _out({"error": "probe token must contain at least 12 URL-safe characters"})
            return 2
        heartbeat = store.base / "S4" / ("spawn-probe-%s.heartbeat" % token)
        payload = {
            "schema_version": "spawn-probe-challenge-v1",
            "stage": "S4",
            "probe": "spawn-preflight",
            "token": token,
            "heartbeat_file": str(heartbeat),
            "expected_heartbeat": "PROBE %s" % token,
            "expected_reply": "PROBE-DONE %s" % token,
            "issued_at": datetime.now().isoformat(timespec="seconds"),
            "claim_status": "not-a-finding",
        }
        out = store.write_artifact("S4", "spawn-probe-challenge.json", payload)
        _out({"written_to": str(out), "heartbeat_file": str(heartbeat),
              "token": token, "expected_reply": payload["expected_reply"],
              "claim_status": "not-a-finding"})
        return 0

    if not getattr(args, "status", None):
        _out({"error": "--status is required unless --prepare is used"})
        return 2
    challenge = store.read_artifact("S4", "spawn-probe-challenge.json")
    challenge = challenge if isinstance(challenge, dict) else {}
    token = str(challenge.get("token") or "")
    heartbeat = Path(str(challenge.get("heartbeat_file") or
                         (store.base / "S4" / "spawn-probe.heartbeat")))
    expected_heartbeat = str(challenge.get("expected_heartbeat") or "")
    expected_reply = str(challenge.get("expected_reply") or "")
    heartbeat_lines: List[str] = []
    try:
        if heartbeat.is_file():
            heartbeat_lines = heartbeat.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        heartbeat_lines = []
    heartbeat_valid = bool(expected_heartbeat and
                           expected_heartbeat in [line.strip() for line in heartbeat_lines])
    reply = str(args.reply or "")
    reply_valid = bool(expected_reply and reply.strip() == expected_reply)
    challenge_valid = bool(token and expected_heartbeat and expected_reply)
    requested_ok = args.status == "ok"
    verified = bool(challenge_valid and heartbeat_valid and reply_valid)
    ok = bool(requested_ok and verified)
    requested_symptom = getattr(args, "symptom", None)
    if ok:
        symptom = "ok"
    elif requested_ok and not challenge_valid:
        symptom = "challenge-missing"
    elif requested_ok:
        symptom = "probe-contract-invalid"
    else:
        symptom = requested_symptom or "no-heartbeat-timeout"
    payload = {
        "schema_version": "spawn-probe-v2",
        "stage": "S4",
        "probe": "spawn-preflight",
        "status": "ok" if ok else "degraded",
        "symptom": symptom,
        "observed": {
            "heartbeat_file": str(heartbeat),
            "heartbeat_seen": heartbeat.exists(),
            "heartbeat_line_count": len(heartbeat_lines),
            "heartbeat_token_valid": heartbeat_valid,
            "reply_token_valid": reply_valid,
            "challenge_present": bool(challenge),
            "challenge_valid": challenge_valid,
            "challenge_token": token,
            "wait_seconds": args.wait_seconds,
            "agent_reply": reply,
            "followup_retried": bool(getattr(args, "followup_retried", False)),
        },
        "decision": "parallel-per-candidate" if ok else "host-sequential-whole-round",
        "recorded_at": datetime.now().isoformat(timespec="seconds"),
        "claim_status": "not-a-finding",
    }
    out = store.write_artifact("S4", "spawn-probe.json", payload)
    _out({"written_to": str(out), "decision": payload["decision"],
          "status": payload["status"], "symptom": symptom,
          "verified": verified, "claim_status": "not-a-finding"})
    return 0 if not requested_ok or ok else 2


def _parallel_candidate_id(value: Any) -> str:
    """Return a path-safe bounded candidate identifier, or an empty string."""
    candidate = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", candidate):
        return ""
    return candidate


def _parallel_artifact(store: Any, candidate: str,
                       value: Any) -> Optional[Dict[str, Any]]:
    """Validate one declared S4 matrix artifact without retaining its content."""
    raw = str(value or "").replace("\\", "/").lstrip("/")
    expected_prefix = "S4/matrix-runs/%s/" % candidate
    if not raw.startswith(expected_prefix):
        return None
    try:
        path = (store.base / raw).resolve()
        path.relative_to(store.base.resolve())
    except (OSError, ValueError):
        return None
    if not path.is_file():
        return None
    try:
        size = path.stat().st_size
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None
    if size <= 0:
        return None
    return {"path": raw, "sha256": digest, "size": size}


def cmd_parallel_receipt(args: argparse.Namespace) -> int:
    """Challenge-bind each spawned S4 candidate to a durable matrix receipt.

    Preflight proves task delivery once. This narrower per-candidate contract
    prevents a later generic reply from being mistaken for completed runtime
    work: completion is valid only when a fresh challenge and matrix digest
    agree. It records evidence metadata only, never a vulnerability result.
    """
    from datetime import datetime
    from agent.memory.state import CheckpointStore

    candidate = _parallel_candidate_id(getattr(args, "candidate", ""))
    if not candidate:
        _out({"error": "candidate must be a path-safe id (1-80 chars)"})
        return 2
    store = CheckpointStore(Path(args.workspace), args.target, args.round)
    receipt_name = "parallel-receipt-%s.json" % candidate
    challenge_name = "parallel-receipt-%s.challenge.json" % candidate
    expected_artifact = "S4/matrix-runs/%s/cells.json" % candidate

    if getattr(args, "prepare", False):
        token = str(getattr(args, "token", "") or secrets.token_urlsafe(18))
        token = re.sub(r"[^A-Za-z0-9_-]", "", token)[:96]
        if len(token) < 12:
            _out({"error": "receipt token must contain at least 12 URL-safe characters"})
            return 2
        payload = {
            "schema_version": "parallel-receipt-challenge-v1",
            "stage": "S4",
            "candidate_id": candidate,
            "token": token,
            "expected_artifact": expected_artifact,
            "issued_at": datetime.now().isoformat(timespec="seconds"),
            "claim_status": "not-a-finding",
        }
        out = store.write_artifact("S4", challenge_name, payload)
        _out({"written_to": str(out), "candidate_id": candidate,
              "token": token, "expected_artifact": expected_artifact,
              "claim_status": "not-a-finding"})
        return 0

    challenge = store.read_artifact("S4", challenge_name)
    challenge = challenge if isinstance(challenge, dict) else {}
    challenge_valid = bool(
        challenge.get("schema_version") == "parallel-receipt-challenge-v1"
        and challenge.get("candidate_id") == candidate
        and isinstance(challenge.get("token"), str)
        and len(challenge.get("token")) >= 12
        and challenge.get("expected_artifact") == expected_artifact)

    receipt = store.read_artifact("S4", receipt_name)
    receipt = receipt if isinstance(receipt, dict) else {}
    receipt_matches = bool(
        receipt.get("schema_version") == "parallel-receipt-v1"
        and receipt.get("candidate_id") == candidate
        and receipt.get("token") == challenge.get("token"))

    if getattr(args, "inspect", False):
        if not receipt_matches:
            _out({"candidate_id": candidate, "status": "missing",
                  "progress_count": 0, "last_progress": None,
                  "artifact_count": 0, "claim_status": "not-a-finding"})
            return 0
        events = receipt.get("events") if isinstance(receipt.get("events"), list) else []
        last_progress = next((event for event in reversed(events)
                              if isinstance(event, dict)
                              and event.get("kind") == "progress"), None)
        artifacts = receipt.get("artifacts") if isinstance(
            receipt.get("artifacts"), list) else []
        _out({
            "candidate_id": candidate,
            "status": receipt.get("status", "unknown"),
            "started_at": receipt.get("started_at"),
            "updated_at": receipt.get("updated_at"),
            "progress_count": int(receipt.get("progress_count") or 0),
            "last_progress": last_progress,
            "artifact_count": len(artifacts),
            "claim_status": "not-a-finding",
        })
        return 0

    if getattr(args, "verify", False):
        artifacts = receipt.get("artifacts") if isinstance(
            receipt.get("artifacts"), list) else []
        valid_artifacts = []
        for item in artifacts[:8]:
            if not isinstance(item, dict):
                continue
            checked = _parallel_artifact(store, candidate, item.get("path"))
            if checked and checked == {key: item.get(key) for key in checked}:
                valid_artifacts.append(checked)
        expected_present = any(row["path"] == expected_artifact
                               for row in valid_artifacts)
        verified = bool(
            challenge_valid
            and receipt.get("schema_version") == "parallel-receipt-v1"
            and receipt.get("candidate_id") == candidate
            and receipt.get("token") == challenge.get("token")
            and receipt.get("status") == "completed"
            and expected_present)
        _out({
            "candidate_id": candidate,
            "verified": verified,
            "decision": ("accept-runtime-artifacts" if verified else
                         "preserve-partial-and-run-host-sequentially"),
            "challenge_valid": challenge_valid,
            "receipt_status": receipt.get("status", "missing"),
            "expected_artifact_present": expected_present,
            "valid_artifact_count": len(valid_artifacts),
            "claim_status": "not-a-finding",
        })
        return 0 if verified else 2

    status = str(getattr(args, "status", "") or "").lower()
    if status not in {"received", "progress", "completed", "partial"}:
        _out({"error": "--status received|progress|completed|partial is required unless --prepare/--verify"})
        return 2
    supplied_token = str(getattr(args, "token", "") or "")
    artifact_rows = []
    for value in (getattr(args, "artifact", None) or [])[:8]:
        checked = _parallel_artifact(store, candidate, value)
        if checked and checked not in artifact_rows:
            artifact_rows.append(checked)
    if not challenge_valid or supplied_token != challenge.get("token"):
        _out({"error": "receipt challenge missing or token mismatch",
              "candidate_id": candidate})
        return 2
    prior_artifacts = []
    if receipt_matches:
        for item in (receipt.get("artifacts") or [])[:8]:
            if not isinstance(item, dict):
                continue
            checked = _parallel_artifact(store, candidate, item.get("path"))
            if checked and checked == {key: item.get(key) for key in checked}:
                prior_artifacts.append(checked)
    all_artifacts = list(prior_artifacts)
    for row in artifact_rows:
        if row not in all_artifacts:
            all_artifacts.append(row)
    all_artifacts = all_artifacts[:8]
    expected_present = any(row["path"] == expected_artifact
                           for row in all_artifacts)
    if status == "progress":
        step = " ".join(str(getattr(args, "progress_step", "") or "").split())
        step = "".join(ch for ch in step if ch.isprintable())[:120]
        if not step:
            _out({"error": "--status progress requires a concise --progress-step",
                  "candidate_id": candidate, "claim_status": "not-a-finding"})
            return 2
    else:
        step = {"received": "task-accepted", "partial": "partial-result",
                "completed": "matrix-complete"}[status]
    if status == "completed" and not expected_present:
        _out({"error": "completed receipt requires %s" % expected_artifact,
              "candidate_id": candidate, "claim_status": "not-a-finding"})
        return 2
    now = datetime.now().isoformat(timespec="seconds")
    events = list(receipt.get("events") or []) if receipt_matches else []
    events = [event for event in events if isinstance(event, dict)][-15:]
    event = {"kind": "progress" if status == "progress" else status,
             "step": step, "recorded_at": now}
    if artifact_rows:
        event["artifacts"] = [row["path"] for row in artifact_rows]
    events.append(event)
    progress_count = int(receipt.get("progress_count") or 0) if receipt_matches else 0
    if status == "progress":
        progress_count += 1
    payload = {
        "schema_version": "parallel-receipt-v1",
        "stage": "S4",
        "candidate_id": candidate,
        "token": supplied_token,
        "status": ("running" if status in {"received", "progress"} else status),
        "artifacts": all_artifacts,
        "started_at": receipt.get("started_at") if receipt_matches else now,
        "updated_at": now,
        "progress_count": progress_count,
        "events": events[-16:],
        "claim_status": "not-a-finding",
    }
    out = store.write_artifact("S4", receipt_name, payload)
    _out({"written_to": str(out), "candidate_id": candidate, "status": status,
          "progress_count": progress_count,
          "artifact_count": len(all_artifacts), "claim_status": "not-a-finding"})
    return 0



