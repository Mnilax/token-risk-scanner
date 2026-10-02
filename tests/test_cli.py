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
