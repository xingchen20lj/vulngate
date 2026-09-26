"""Contract tests: every CLI invocation documented in SKILL.md must be real.

A host agent following ``skills/vulngate-audit/SKILL.md`` literally is the whole
point of the execution contract, so a documented flag that ``argparse`` rejects
is a documentation bug with the same effect as a code bug: the agent hard-fails
at S1/S4/S5 with no clue that the document, not the target, is at fault.

Issue #1 reported three such invocations (six lines: normative English plus the
中文参考版).  These tests parse every ``agent_cli.py <subcommand> --flag``
occurrence out of SKILL.md and validate the subcommand, each flag, and each
``<a|b|c>`` choice list against the real parsers -- so the next drift fails here
instead of in someone's audit run.
"""

import argparse
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "skills" / "vulngate-audit"
SKILL_MD = SKILL_ROOT / "SKILL.md"
RUN_AGENT = REPO_ROOT / "scripts" / "agent" / "autonomous" / "run_agent.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import agent_cli  # noqa: E402  (path is set up above)


# "agent_cli.py source-map" -> "source-map"
SUB_RE = re.compile(r"agent_cli\.py\s+([a-z][a-z0-9-]*)")
# "--root" / "--target-dir", but not the "--" inside a longer token
FLAG_RE = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")
# "--preset <parsers|http|expression|io|exec|config|native|all>" -- the "|" is
# what distinguishes a choice list from a plain placeholder like "<tier>".
CHOICES_RE = re.compile(r"(--[a-z][a-z0-9-]*)\s+<([A-Za-z0-9_]+(?:\|[A-Za-z0-9_]+)+)>")


def _subcommands():
    parser = agent_cli.build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    raise AssertionError("agent_cli.build_parser() exposes no subparsers")


def _option_strings(parser):
    return {s for a in parser._actions for s in a.option_strings}


def _choice_map(parser):
    out = {}
    for action in parser._actions:
        if action.option_strings and action.choices:
            out[action.option_strings[0]] = {str(c) for c in action.choices}
    return out


class SkillCliContractTests(unittest.TestCase):
    """The skill and its phase references must document valid CLI usage."""

    @classmethod
    def setUpClass(cls):
        cls.lines = [
            line
            for path in sorted(SKILL_ROOT.rglob("*.md"))
            for line in path.read_text(encoding="utf-8").splitlines()
        ]
        cls.subs = _subcommands()

    def _invocations(self):
        for lineno, line in enumerate(self.lines, 1):
            match = SUB_RE.search(line)
            if match:
                yield lineno, line, match.group(1)

    def test_the_document_does_contain_invocations(self):
        # Without this, a broken pattern would make every other test pass on an
        # empty set -- the false-negative shape this whole file exists to stop.
        found = list(self._invocations())
        self.assertGreaterEqual(len(found), 10, f"only found {len(found)} invocations")

    def test_every_documented_subcommand_exists(self):
        bad = [(n, s) for n, _, s in self._invocations() if s not in self.subs]
        self.assertEqual(bad, [], f"skill documentation lists unknown subcommands: {bad}")

    def test_every_documented_flag_exists(self):
        bad = []
        for lineno, line, sub in self._invocations():
            known = _option_strings(self.subs[sub])
            for flag in FLAG_RE.findall(line):
                if flag not in known:
                    bad.append(f"skill documentation:{lineno}  {sub} {flag}")
        self.assertEqual(
            bad, [], "documented flags that argparse rejects:\n  " + "\n  ".join(bad)
        )

    def test_documented_choice_lists_are_complete(self):
        """``--flag <a|b|c>`` must list the same set argparse accepts.

        The original report included this: ``--preset`` omitted ``native`` while
        the same document introduced the native preset two sections earlier.
        """
        bad = []
        for lineno, line, sub in self._invocations():
            choices = _choice_map(self.subs[sub])
            for flag, spec in CHOICES_RE.findall(line):
                actual = choices.get(flag)
                if actual is None:
                    continue  # free-form value: nothing to compare against
                documented = set(spec.split("|"))
                if documented != actual:
                    bad.append(
                        f"skill documentation:{lineno}  {sub} {flag}: documented "
                        f"{sorted(documented)} != actual {sorted(actual)}"
                    )
        self.assertEqual(
            bad, [], "incomplete or stale choice lists:\n  " + "\n  ".join(bad)
        )


class RunPipelineContractTests(unittest.TestCase):
    """``run_pipeline.sh --flag`` must exist in run_agent's parser.

    run_pipeline.sh execs ``python3 -m agent.autonomous.run_agent "$@"``, so the
    flags its documentation shows belong to that parser.  It is built inside
    ``main()`` rather than in a reusable function, so it is read from source.
    """

    @classmethod
    def setUpClass(cls):
        cls.lines = SKILL_MD.read_text(encoding="utf-8").splitlines()
        # Parser construction moved with the reporting phase; the facade still
        # owns the module CLI entrypoint, so inspect both compatibility files.
        src = "\n".join([
            RUN_AGENT.read_text(encoding="utf-8"),
            (RUN_AGENT.parent / "reporting.py").read_text(encoding="utf-8"),
        ])
        cls.known = set(re.findall(r'add_argument\(\s*"(--[a-z][a-z0-9-]*)"', src))

    def _invocations(self):
        for lineno, line in enumerate(self.lines, 1):
            if "run_pipeline.sh" in line:
                yield lineno, line

    def test_the_parser_flags_were_found(self):
        self.assertGreaterEqual(
            len(self.known), 5, f"no add_argument() flags parsed from {RUN_AGENT.name}"
        )

    def test_every_documented_flag_exists(self):
        bad = []
        for lineno, line in self._invocations():
            for flag in FLAG_RE.findall(line):
                if flag not in self.known:
                    bad.append(f"SKILL.md:{lineno}  run_pipeline.sh {flag}")
        self.assertEqual(
            bad, [], "documented flags missing from run_agent:\n  " + "\n  ".join(bad)
        )


if __name__ == "__main__":
    unittest.main()
