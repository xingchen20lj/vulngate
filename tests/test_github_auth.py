import os
import unittest
from unittest.mock import patch

from agent.tools.github_auth import github_token_source, resolve_github_token


class GithubAuthTests(unittest.TestCase):
    def test_environment_token_wins_without_invoking_gh(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "env-token"}, clear=True), \
                patch("agent.tools.github_auth.shutil.which") as which:
            self.assertEqual(resolve_github_token(), "env-token")
            self.assertEqual(github_token_source(), "GITHUB_TOKEN")
            which.assert_not_called()

    def test_logged_in_gh_keychain_is_detected_without_logging_token(self):
        completed = type("Completed", (), {"returncode": 0, "stdout": "keychain-token\n"})()
        with patch.dict(os.environ, {}, clear=True), \
                patch("agent.tools.github_auth.shutil.which", return_value="/usr/local/bin/gh"), \
                patch("agent.tools.github_auth.subprocess.run", return_value=completed) as run:
            self.assertEqual(resolve_github_token(), "keychain-token")
            self.assertEqual(github_token_source(), "gh-keychain")
            self.assertNotIn("keychain-token", str(run.call_args))

    def test_missing_gh_is_reported_as_missing(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch("agent.tools.github_auth.shutil.which", return_value=None):
            self.assertEqual(resolve_github_token(), "")
            self.assertEqual(github_token_source(), "missing")


if __name__ == "__main__":
    unittest.main()
