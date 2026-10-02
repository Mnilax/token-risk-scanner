from io import StringIO
import re

from rich.console import Console
from typer.testing import CliRunner

from scanner import cli
from scanner.models import TokenInfo
from scanner.score import score_token


def test_documented_scan_subcommand(monkeypatch):
    report = score_token(TokenInfo(chain="eth", address="0x1234"))
    report.data_errors = ["provider offline"]
    monkeypatch.setattr(cli, "analyze_token_sync", lambda chain, address: report)
    result = CliRunner().invoke(cli.app, ["scan", "eth", "0x1234"])
    assert result.exit_code == 0, result.output
    assert "UNKNOWN" in result.output and "provider offline" in result.output


def test_confirmed_honeypot_summary_is_high_risk_and_red(monkeypatch):
    report = score_token(TokenInfo(chain="eth", address="0x1234", is_honeypot=True))
    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(
        file=output, force_terminal=True, color_system="standard", no_color=False,
        legacy_windows=False, width=120,
    ))
    monkeypatch.setattr(cli, "analyze_token_sync", lambda chain, address: report)
    result = CliRunner().invoke(cli.app, ["scan", "eth", "0x1234"])
    assert result.exit_code == 0, result.output
    rendered = output.getvalue()
    plain = re.sub(r"\x1b\[[0-9;]*m", "", rendered)
    assert "40/100" in plain and "HIGH RISK" in plain
    assert "Proceed with caution" not in plain
    assert "\x1b[31mHIGH RISK" in rendered
