import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import httpx
from cli.app import _print_stage, build_parser, run_cli
from core.checker import NetworkChecker
from core.models import CheckReport, Outcome, StageResult
from rich.console import Console


class ExternalInputTests(unittest.TestCase):
    def test_markup_in_invalid_domain_does_not_abort_following_domains(self):
        with tempfile.TemporaryDirectory() as tmp, patch("cli.app.NetworkChecker") as factory, contextlib.redirect_stdout(io.StringIO()) as out:
            factory.return_value.check.side_effect = [ValueError("bad [/red]"), CheckReport("example.com")]
            path = Path(tmp) / "report.json"
            code = run_cli(build_parser().parse_args(["[/red]", "example.com", "--json", str(path)]))
            self.assertEqual(code, 1)
            self.assertEqual(factory.return_value.check.call_count, 2)
            self.assertEqual(json.loads(path.read_text())[0]["domain"], "example.com")
            self.assertIn("[/red]", out.getvalue())

    def test_stage_controls_and_markup_are_rendered_literally(self):
        out = io.StringIO()
        _print_stage(Console(file=out, force_terminal=False, width=140), StageResult("[/red]", Outcome.WARNING, "untrusted\x1b[31m [/bold]"))
        self.assertNotIn("\x1b", out.getvalue())
        self.assertIn("\\x1b[31m", out.getvalue())
        self.assertIn("[/bold]", out.getvalue())

    def test_invalid_hostnames_rejected_before_network(self):
        for value in ("[/red]", "bad:443", "-bad.example", "bad-.example", "bad..example", "example.com..", "bad_name.example", "bad\x00.example", "https://bad\t.example/", "a" * 64 + ".example"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                NetworkChecker._normalise_domain(value)
        self.assertEqual(NetworkChecker._normalise_domain("https://EXAMPLE.com/path"), "example.com")
        self.assertEqual(NetworkChecker._normalise_domain("пример.рф."), "xn--e1afmkfd.xn--p1ai")

    def test_idna_expansion_checks_total_hostname_length(self):
        label = "я" * 30
        name = ".".join([label] * 7)
        self.assertLess(len(name), 253)
        with self.assertRaises(ValueError):
            NetworkChecker._normalise_domain(name)

    def test_bad_doh_shapes_raise_provider_error_not_type_errors(self):
        payloads = ([], {"Answer": None}, {"Answer": [None]}, {"Answer": [{"data": 123}]}, {"Status": []}, {"Status": 3}, {"Answer": [{"data": "not-an-ip"}]}, {"Answer": [{"data": "192.0.2.1", "type": []}]}, {"Answer": [{"data": "2001:db8::1", "type": 1}]})
        for payload in payloads:
            with self.subTest(payload=payload), patch("core.checker.httpx.Client") as client:
                client.return_value.__enter__.return_value.get.return_value = httpx.Response(200, json=payload, request=httpx.Request("GET", "https://resolver.example"))
                with self.assertRaises(ValueError):
                    NetworkChecker()._resolve_doh("https://resolver.example", "example.com")

    def test_doh_cname_is_skipped_and_addresses_normalized(self):
        payloads = [
            {"Status": 0, "Answer": [{"type": 5, "data": "alias.example"}, {"type": 1, "data": "192.0.2.1"}]},
            {"Status": 0, "Answer": [{"type": 28, "data": "2001:0db8::1"}]},
        ]
        with patch("core.checker.httpx.Client") as client:
            client.return_value.__enter__.return_value.get.side_effect = [httpx.Response(200, json=p, request=httpx.Request("GET", "https://resolver.example")) for p in payloads]
            self.assertEqual(NetworkChecker()._resolve_doh("https://resolver.example", "example.com"), ["192.0.2.1", "2001:db8::1"])

    def test_bad_doh_provider_does_not_erase_other_provider(self):
        def response(endpoint, **kwargs):
            payload = [] if "cloudflare" in endpoint else {"Status": 0, "Answer": [{"type": 1, "data": "192.0.2.1"}] if kwargs["params"]["type"] == "A" else []}
            return httpx.Response(200, json=payload, request=httpx.Request("GET", endpoint))
        checker = NetworkChecker()
        with patch("core.checker.httpx.Client") as client, patch.object(checker, "_resolve_system", return_value=[]), patch.object(checker, "_check_tcp"), patch.object(checker, "_check_tls"), patch.object(checker, "_check_http"):
            client.return_value.__enter__.return_value.get.side_effect = response
            report = checker.check("example.com")
        self.assertEqual(report.doh_ips["google"], ["192.0.2.1"])
        self.assertEqual(report.doh_ips["cloudflare"], [])
        stage = next(s for s in report.stages if s.stage == "DNS (DoH)")
        self.assertIn("cloudflare", stage.details["errors"])


class GuiFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Test actual file-dialog callback logic without display/Tk dependencies.
        ctk = types.ModuleType("customtkinter")
        ctk.CTk = object
        tk = types.ModuleType("tkinter")
        tk.filedialog, tk.messagebox = Mock(), Mock()
        source = Path(__file__).resolve().parents[1] / "gui/app.py"
        spec = importlib.util.spec_from_file_location("gui_callback_fixture", source)
        module = importlib.util.module_from_spec(spec)
        with patch.dict("sys.modules", {"customtkinter": ctk, "tkinter": tk}):
            spec.loader.exec_module(module)
        cls.gui = module

    def setUp(self):
        self.gui.filedialog.reset_mock()
        self.gui.messagebox.reset_mock()

    def test_bad_utf8_shows_error_without_mutating_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "domains.txt"
            path.write_bytes(b"\xff")
            self.gui.filedialog.askopenfilename.return_value = str(path)
            app = types.SimpleNamespace(domain=Mock())
            self.gui.NetDiagApp._choose_file(app)
            self.gui.messagebox.showerror.assert_called_once()
            app.domain.delete.assert_not_called()

    def test_valid_file_loads_and_missing_file_is_actionable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "domains.txt"
            path.write_text("# fixture\nexample.com\n\nexample.org\n", encoding="utf-8")
            self.gui.filedialog.askopenfilename.return_value = str(path)
            app = types.SimpleNamespace(domain=Mock())
            self.gui.NetDiagApp._choose_file(app)
            app.domain.insert.assert_called_once_with(0, "example.com example.org")
            self.gui.filedialog.askopenfilename.return_value = str(path.parent / "missing")
            self.gui.NetDiagApp._choose_file(app)
            self.gui.messagebox.showerror.assert_called_once()
