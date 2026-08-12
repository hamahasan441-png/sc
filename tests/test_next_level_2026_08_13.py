#!/usr/bin/env python3
"""Next-level hardening regressions (2026-08-13)."""

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPluginSha256Gate(unittest.TestCase):
    def test_unsigned_disk_plugin_refused(self):
        from core.plugin_system import PluginManager

        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "evil"
            d.mkdir()
            (d / "__init__.py").write_text(
                "plugin_info={'name':'evil'}\nclass PluginScanner:\n    def run(self,t,p): return []\n"
            )
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("ATOMIC_ALLOW_UNSIGNED_PLUGINS", None)
                pm = PluginManager(plugin_dir=tmp)
                self.assertIsNone(pm.load_plugin("evil"))

    def test_matching_manifest_loads(self):
        from core.plugin_system import PluginManager

        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "ok"
            d.mkdir()
            src = "plugin_info={'name':'ok'}\nclass PluginScanner:\n    def run(self,t,p): return []\n"
            init = d / "__init__.py"
            init.write_text(src)
            digest = hashlib.sha256(src.encode()).hexdigest()
            (d / "PLUGIN.sha256").write_text(digest + "\n")
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("ATOMIC_ALLOW_UNSIGNED_PLUGINS", None)
                pm = PluginManager(plugin_dir=tmp)
                info = pm.load_plugin("ok")
                self.assertIsNotNone(info)
                self.assertEqual(info.name, "ok")

    def test_tampered_manifest_refused(self):
        from core.plugin_system import PluginManager

        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "bad"
            d.mkdir()
            (d / "__init__.py").write_text("plugin_info={'name':'bad'}\n")
            (d / "PLUGIN.sha256").write_text("0" * 64 + "\n")
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("ATOMIC_ALLOW_UNSIGNED_PLUGINS", None)
                pm = PluginManager(plugin_dir=tmp)
                self.assertIsNone(pm.load_plugin("bad"))


class TestOllamaHostSSRF(unittest.TestCase):
    def test_remote_host_rewritten_to_loopback(self):
        from web import app as webapp

        with patch.dict(
            os.environ,
            {"OLLAMA_HOST": "http://169.254.169.254/latest", "ATOMIC_OLLAMA_ALLOW_REMOTE": ""},
            clear=False,
        ):
            os.environ.pop("ATOMIC_OLLAMA_ALLOW_REMOTE", None)
            self.assertEqual(webapp._ollama_host(), "http://localhost:11434")

    def test_localhost_preserved(self):
        from web import app as webapp

        with patch.dict(os.environ, {"OLLAMA_HOST": "http://127.0.0.1:11434"}, clear=False):
            os.environ.pop("ATOMIC_OLLAMA_ALLOW_REMOTE", None)
            self.assertEqual(webapp._ollama_host(), "http://127.0.0.1:11434")

    def test_remote_opt_in(self):
        from web import app as webapp

        with patch.dict(
            os.environ,
            {"OLLAMA_HOST": "http://ollama.internal:11434", "ATOMIC_OLLAMA_ALLOW_REMOTE": "1"},
            clear=False,
        ):
            self.assertEqual(webapp._ollama_host(), "http://ollama.internal:11434")


class TestChatSenderFromPrincipal(unittest.TestCase):
    def test_authenticated_sender_overrides_body(self):
        from web import app as webapp

        webapp.app.config["TESTING"] = True
        webapp._chat_messages.clear()
        with webapp.app.test_request_context(
            "/api/chat/messages",
            method="POST",
            json={"sender": "attacker", "message": "hi"},
        ):
            with patch.object(webapp, "_get_current_user", return_value={"sub": "alice", "role": "admin"}):
                resp = webapp.post_chat_message()
        # Flask view may return (response, status)
        payload = resp[0].get_json() if isinstance(resp, tuple) else resp.get_json()
        self.assertEqual(payload["data"]["sender"], "alice")
        webapp.app.config["TESTING"] = False


class TestToolScopeFailClosed(unittest.TestCase):
    def test_auth_required_no_allowlist_denies(self):
        from web import app as webapp

        webapp.app.config["TESTING"] = False
        with patch.object(webapp, "_AUTH_REQUIRED", True):
            with patch.dict(os.environ, {"ATOMIC_ALLOWED_DOMAINS": "", "ATOMIC_TOOL_SCOPE_STRICT": ""}, clear=False):
                os.environ.pop("ATOMIC_ALLOWED_DOMAINS", None)
                os.environ.pop("ATOMIC_TOOL_SCOPE_STRICT", None)
                self.assertFalse(webapp._tool_target_in_configured_scope("https://evil.example"))
        webapp.app.config["TESTING"] = False
