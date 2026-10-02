"""Tests for the scoring module — deterministic, no I/O."""

from scanner.models import TokenInfo, Severity
from scanner.score import score_token


def test_clean_token():
    """A completely clean token should get minimal risk."""
    token = TokenInfo(
        chain="ethereum",
        address="0x1234",
        is_honeypot=False,
        is_mintable=False,
        is_ownership_renounced=True,
        is_lp_locked=True,
        lp_lock_percent=100.0,
        top10_holder_percent=25.0,
        buy_tax=0.5,
        sell_tax=0.5,
        is_proxy=False,
        is_open_source=True,
    )
    report = score_token(token)
    assert report.risk_score == 0
    assert "MINIMAL" in report.verdict
    greens = [f for f in report.flags if f.severity == Severity.GREEN]
    assert len(greens) >= 4


def test_honeypot():
    """Honeypot should be high risk."""
    token = TokenInfo(
        chain="ethereum",
        address="0xdead",
        is_honeypot=True,
        honeypot_reason="Cannot sell",
    )
    report = score_token(token)
    assert report.risk_score >= 40
    reds = [f for f in report.flags if f.severity == Severity.RED]
    assert any("Honeypot" in f.label for f in reds)


def test_mintable_token():
    """Active mint authority should add significant risk."""
    token = TokenInfo(
        chain="bsc",
        address="0xmint",
        is_mintable=True,
        is_honeypot=False,
    )
    report = score_token(token)
    assert report.risk_score >= 25
    reds = [f for f in report.flags if f.severity == Severity.RED]
    assert any("Mint" in f.label for f in reds)


def test_high_holder_concentration():
    """Extreme holder concentration should flag RED."""
    token = TokenInfo(
        chain="ethereum",
        address="0xwhale",
        top10_holder_percent=85.0,
    )
    report = score_token(token)
    assert report.risk_score >= 20
    reds = [f for f in report.flags if f.severity == Severity.RED]
    assert any("concentration" in f.label.lower() for f in reds)


def test_moderate_holder_concentration():
    """Moderate concentration should flag YELLOW."""
    token = TokenInfo(
        chain="ethereum",
        address="0xmod",
        top10_holder_percent=55.0,
    )
    report = score_token(token)
    yellows = [f for f in report.flags if f.severity == Severity.YELLOW]
    assert any("concentration" in f.label.lower() for f in yellows)


def test_high_sell_tax():
    """Extreme sell tax should be RED."""
    token = TokenInfo(
        chain="bsc",
        address="0xtax",
        sell_tax=30.0,
        buy_tax=2.0,
    )
    report = score_token(token)
    reds = [f for f in report.flags if f.severity == Severity.RED]
    assert any("sell tax" in f.label.lower() for f in reds)


def test_unlocked_lp():
    """Unlocked LP should flag YELLOW."""
    token = TokenInfo(
        chain="ethereum",
        address="0xlp",
        is_lp_locked=False,
    )
    report = score_token(token)
    yellows = [f for f in report.flags if f.severity == Severity.YELLOW]
    assert any("LP" in f.label or "Liquidity" in f.label for f in yellows)


def test_worst_case_capped_at_100():
    """Score should never exceed 100."""
    token = TokenInfo(
        chain="bsc",
        address="0xworst",
        is_honeypot=True,
        is_mintable=True,
        is_ownership_renounced=False,
        is_lp_locked=False,
        top10_holder_percent=95.0,
        buy_tax=50.0,
        sell_tax=50.0,
        is_proxy=True,
        is_open_source=False,
    )
    report = score_token(token)
    assert report.risk_score == 100
    assert "HIGH" in report.verdict


def test_empty_token_info():
    """Unknown data should produce a report without crashing."""
    token = TokenInfo(chain="ethereum", address="0xunknown")
    report = score_token(token)
    assert report.risk_score == 0
    assert len(report.flags) == 0
    assert report.verdict.startswith("UNKNOWN")
