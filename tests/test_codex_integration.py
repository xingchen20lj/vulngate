"""Codex packaging and host-driven acceptance tests (offline)."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from agent.orchestrator import pipeline
from agent.orchestrator.config import TargetConfig
from agent.orchestrator.stages import StageContext


def load_adapter(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'macos/bin' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PipelineSelectionTests(unittest.TestCase):
    def exercise(self, resume, selection):
        with tempfile.TemporaryDirectory() as td:
            cfg = TargetConfig('fixture', '2026-09-16', candidates=[
                {'candidate_id': 'deferred', 'surface': 'exec'}])
            ctx = StageContext(Path(td), 'fixture', 1, cfg, offline=True)
            ctx.store.save_stage('S1', {'complete': True})
            for stage in ('S4', 'S5', 'S6', 'S7', 'S8'):
                ctx.store.save_stage(stage, {'complete': True})
            if resume:
                ctx.store.save_stage('S2', {'candidates': selection})
            seen = []
            def audit(context):
                seen.extend(context.config.candidates)
                return {'complete': True}
            with patch.object(pipeline, 'run_s2', return_value={'candidates': selection}), \
                    patch.object(pipeline, 'run_s3', side_effect=audit), \
                    contextlib.redirect_stdout(io.StringIO()):
                pipeline.run_round(ctx)
            self.assertEqual(selection, seen)

    def test_fresh_round_audits_generated_selection_only(self):
        self.exercise(False, [{'candidate_id': 'ctl-new', 'surface': 'authz'}])

    def test_resume_restores_selection(self):
        self.exercise(True, [{'candidate_id': 'ctl-new', 'surface': 'authz'}])

    def test_empty_cached_selection_does_not_restore_deferred_pool(self):
        self.exercise(True, [])


class NativeLauncherTests(unittest.TestCase):
    def test_default_plugin_is_the_loaded_script_not_a_host_cache(self):
        runner = load_adapter('vg-run')
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(ROOT, runner.find_plugin(''))

    def test_explicit_missing_plugin_does_not_fall_back(self):
        runner = load_adapter('vg-run')
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit):
                runner.find_plugin(td)

    def test_audit_root_uses_native_workspace_option_and_restores_cwd(self):
        runner = load_adapter('vg-run')
        original = pipeline.WORKSPACE
        cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as td:
            with patch.object(pipeline, 'main', return_value=0) as main, \
                    contextlib.redirect_stdout(io.StringIO()):
                rc = runner.main(['--plugin', str(ROOT), '--audit-root', td,
                                  '--target', 'fixture', '--config', 'targets/fixture.json'])
            self.assertEqual(0, rc)
            self.assertEqual(['--workspace', str(Path(td).resolve())], main.call_args.args[0][-2:])
            self.assertEqual(original, pipeline.WORKSPACE)
            self.assertEqual(cwd, Path.cwd())


class CodexInstallerTests(unittest.TestCase):
    def test_install_and_update_ship_only_plugin_payload(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            source = base / 'source'
            shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(
                '.git', '__pycache__', 'state', 'ledger', 'reports', 'poc'))
            for name in ('state', 'ledger', 'reports', 'poc', '.vulngate-macos-backup', '.github'):
                (source / name).mkdir(exist_ok=True)
                (source / name / 'private-marker').write_text('must not ship')
            (source / '.env').write_text('PRIVATE=not-a-real-secret')
            marketplace = base / 'market/marketplace.json'
            marketplace.parent.mkdir()
            other = {'name': 'other', 'source': {'source': 'local', 'path': './plugins/other'}}
            marketplace.write_text(json.dumps({'name': 'personal', 'interface': {
                'displayName': 'Existing'}, 'plugins': [other]}))
            env = dict(os.environ, PLUGIN_HOME=str(base / 'plugins'),
                       VULNGATE_MARKETPLACE=str(marketplace))
            dest = base / 'plugins/vulngate'
            for _ in range(2):
                result = subprocess.run(['bash', str(source / 'install.sh'), '--no-enable'],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            data = json.loads(marketplace.read_text())
            self.assertEqual('Existing', data['interface']['displayName'])
            self.assertEqual(other, data['plugins'][0])
            self.assertEqual(1, sum(p['name'] == 'vulngate' for p in data['plugins']))
            manifest = json.loads((dest / '.codex-plugin/plugin.json').read_text())
            self.assertEqual('vulngate', manifest['name'])
            self.assertIn('+codex.', manifest['version'])
            for name in ('macos/bin/vg-run.py', 'scripts/agent/analysis/coverage.py',
                         'skills/vulngate-audit/SKILL.md'):
                self.assertTrue((dest / name).is_file(), name)
            for name in ('state', 'ledger', 'reports', 'poc', '.env', '.gitignore', '.github',
                         '.vulngate-macos-backup', '.foreign-plugin', '.foreign-agent-state'):
                self.assertFalse((dest / name).exists(), name)
            result = subprocess.run([sys.executable, str(dest / 'scripts/agent_cli.py'),
                                     'coverage', '--help'], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)


class AsarIntegrationTests(unittest.TestCase):
    def archive(self, path, files):
        # Chromium Pickle layout as written by electron/asar, including padding.
        index = {'files': {}}
        payload = b''
        for name, content in files.items():
            index['files'][name] = {'size': len(content), 'offset': str(len(payload))}
            payload += content
        data = json.dumps(index, ensure_ascii=False).encode()
        string = struct.pack('<I', len(data)) + data
        string += b'\0' * (-len(string) % 4)
        header = struct.pack('<I', len(string)) + string
        path.write_bytes(struct.pack('<II', 4, len(header)) + header + payload)

    def test_extract_standard_archive_and_restore_typescript(self):
        tool = load_adapter('asar_tool')
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            archive = base / 'app.asar'
            source = 'export const greeting = "你好";\n'
            source_map = json.dumps({'version': 3, 'sources': ['webpack://app/src/main.ts'],
                                     'sourcesContent': [source]}).encode()
            self.archive(archive, {'app.js': b'console.log("hello");', 'app.js.map': source_map})
            result = tool.extract(archive, base / 'out', True)
            self.assertEqual(2, result['written'])
            self.assertEqual(1, result['restored_sources'])
            self.assertEqual(source, (base / 'out/__sources__/app/src/main.ts').read_text())

    def test_reject_truncated_header(self):
        tool = load_adapter('asar_tool')
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / 'app.asar'
            self.archive(archive, {'main.js': b'x'})
            archive.write_bytes(archive.read_bytes()[:18])
            with self.assertRaises(ValueError):
                tool.read_index(archive)

    def test_reject_parent_entry_and_output_symlink(self):
        tool = load_adapter('asar_tool')
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            archive = base / 'app.asar'
            self.archive(archive, {'../escape.js': b'x'})
            with self.assertRaises(ValueError):
                tool.extract(archive, base / 'out', False)
            self.archive(archive, {'main.js': b'x'})
            (base / 'outside.js').write_text('unchanged')
            (base / 'out').mkdir(exist_ok=True)
            (base / 'out/main.js').symlink_to(base / 'outside.js')
            with self.assertRaises(ValueError):
                tool.extract(archive, base / 'out', False)
            self.assertEqual('unchanged', (base / 'outside.js').read_text())


if __name__ == '__main__':
    unittest.main()
