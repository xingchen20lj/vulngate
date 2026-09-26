#!/usr/bin/env python3
"""Build a deterministic, inspectable VulnGate release artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import subprocess
import tarfile
from io import BytesIO
from pathlib import Path
from typing import Dict, List


def _tracked(root: Path) -> List[str]:
    result = subprocess.run(["git", "ls-files", "-z"], cwd=root,
                            stdout=subprocess.PIPE, check=True)
    values = result.stdout.decode("utf-8").split("\0")
    blocked = ("/state/", "/ledger/", "/reports/", "/poc/", "credentials")
    return sorted(path for path in values if path and not any(
        marker in "/" + path for marker in blocked))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(root: Path, tag: str, out: Path) -> Dict[str, str]:
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("release tag must be vMAJOR.MINOR.PATCH")
    manifest = json.loads((root / ".codex-plugin" / "plugin.json").read_text())
    base_version = str(manifest.get("version", "")).split("+", 1)[0]
    if base_version != tag[1:]:
        raise ValueError("manifest version %s does not match %s" % (base_version, tag))
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if tag[1:] not in changelog:
        raise ValueError("CHANGELOG.md has no entry for %s" % tag[1:])
    paths = _tracked(root)
    sbom: List[Dict[str, object]] = []
    tar_buffer = BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        for relative in paths:
            source = root / relative
            if not source.is_file():
                continue
            content = source.read_bytes()
            info = tarfile.TarInfo("vulngate/%s" % relative)
            info.size = len(content)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
            archive.addfile(info, BytesIO(content))
            sbom.append({"path": relative, "size": len(content),
                         "sha256": _sha256(content)})
    archive_bytes = gzip.compress(tar_buffer.getvalue(), mtime=0)
    out.mkdir(parents=True, exist_ok=True)
    artifact = out / ("vulngate-%s.tar.gz" % tag)
    artifact.write_bytes(archive_bytes)
    sbom_path = out / ("vulngate-%s.sbom.json" % tag)
    sbom_path.write_text(json.dumps({"schema_version": "sbom-v1", "tag": tag,
                                     "files": sbom}, indent=2) + "\n")
    sums = {artifact.name: _sha256(archive_bytes), sbom_path.name: _sha256(sbom_path.read_bytes())}
    sums_path = out / "SHA256SUMS"
    sums_path.write_text("".join("%s  %s\n" % (digest, name)
                                  for name, digest in sorted(sums.items())))
    provenance = {
        "schema_version": "vulngate-release-provenance-v1",
        "tag": tag,
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root,
                                           text=True).strip(),
        "artifact_sha256": sums[artifact.name],
        "sbom_sha256": sums[sbom_path.name],
        "reproducible": True,
    }
    (out / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return {"artifact": str(artifact), "sha256": sums[artifact.name],
            "sbom": str(sbom_path), "provenance": str(out / "PROVENANCE.json")}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--out", default="dist")
    args = parser.parse_args()
    result = build(Path(__file__).resolve().parents[1], args.tag,
                   Path(args.out).resolve())
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
