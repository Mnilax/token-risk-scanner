"""Risk scoring — pure functions, no I/O.

Input: TokenInfo signals -> risk score 0-100 + list of flags.
Deterministic and testable.
"""

from __future__ import annotations

from scanner.models import Flag, RiskReport, Severity, TokenInfo

# Thresholds
TOP10_HOLDER_WARN = 50.0  # % held by top 10
TOP10_HOLDER_DANGER = 80.0
BUY_TAX_WARN = 5.0
SELL_TAX_WARN = 10.0
TAX_DANGER = 25.0
LP_LOCK_MIN = 80.0


def score_token(token: TokenInfo) -> RiskReport:
    """Analyze token signals and produce a risk report."""
    flags: list[Flag] = []
    risk_points = 0

    # --- Honeypot (RED — critical) ---
    if token.is_honeypot is True:
        flags.append(Flag(
            Severity.RED,
            "Honeypot detected",
            token.honeypot_reason or "Token appears to be a honeypot — selling may be impossible",
        ))
        risk_points += 40

    elif token.is_honeypot is False:
        flags.append(Flag(Severity.GREEN, "Not a honeypot", "Buy and sell simulation passed"))

    # --- Mint authority (RED) ---
    if token.is_mintable is True:
        flags.append(Flag(
            Severity.RED,
            "Mint authority active",
            "Contract owner can mint unlimited tokens, diluting holders",
        ))
        risk_points += 25
    elif token.is_mintable is False:
        flags.append(Flag(Severity.GREEN, "Mint disabled", "No active mint authority"))

    # --- Ownership renounced (GREEN) ---
    if token.is_ownership_renounced is True:
        flags.append(Flag(
            Severity.GREEN,
            "Ownership renounced",
            "Contract ownership has been renounced",
        ))
    elif token.is_ownership_renounced is False:
        flags.append(Flag(
            Severity.YELLOW,
            "Ownership NOT renounced",
            f"Owner: {token.owner_address or 'unknown'}",
        ))
        risk_points += 10

    # --- LP lock ---
    if token.is_lp_locked is False:
        flags.append(Flag(
            Severity.YELLOW,
            "Liquidity pool NOT locked",
            "LP can be withdrawn at any time (rug risk)",
        ))
        risk_points += 15
    elif token.is_lp_locked is True:
        pct = token.lp_lock_percent
        if pct is not None and pct < LP_LOCK_MIN:
            flags.append(Flag(
                Severity.YELLOW,
                f"LP partially locked ({pct:.0f}%)",
                f"Only {pct:.0f}% of LP is locked — consider >80%",
            ))
            risk_points += 5
        else:
            flags.append(Flag(
                Severity.GREEN,
                "LP locked",
                f"Liquidity locked{f' ({pct:.0f}%)' if pct else ''}",
            ))

    # --- Top-10 holder concentration ---
    if token.top10_holder_percent is not None:
        pct = token.top10_holder_percent
        if pct >= TOP10_HOLDER_DANGER:
            flags.append(Flag(
                Severity.RED,
                f"Extreme holder concentration ({pct:.1f}%)",
                f"Top 10 wallets hold {pct:.1f}% of supply",
            ))
            risk_points += 20
        elif pct >= TOP10_HOLDER_WARN:
            flags.append(Flag(
                Severity.YELLOW,
                f"High holder concentration ({pct:.1f}%)",
                f"Top 10 wallets hold {pct:.1f}% of supply",
            ))
            risk_points += 10
        else:
            flags.append(Flag(
                Severity.GREEN,
                f"Healthy distribution ({pct:.1f}%)",
                f"Top 10 wallets hold {pct:.1f}% of supply",
            ))

    # --- Buy/sell tax ---
    if token.buy_tax is not None:
        if token.buy_tax >= TAX_DANGER:
            flags.append(Flag(
                Severity.RED,
                f"Extreme buy tax ({token.buy_tax:.1f}%)",
                "Dangerously high buy tax",
            ))
            risk_points += 15
        elif token.buy_tax >= BUY_TAX_WARN:
            flags.append(Flag(
                Severity.YELLOW,
                f"High buy tax ({token.buy_tax:.1f}%)",
                f"Buy tax is {token.buy_tax:.1f}%",
            ))
            risk_points += 5

    if token.sell_tax is not None:
        if token.sell_tax >= TAX_DANGER:
            flags.append(Flag(
                Severity.RED,
                f"Extreme sell tax ({token.sell_tax:.1f}%)",
                "Dangerously high sell tax — may be unable to sell",
            ))
            risk_points += 20
        elif token.sell_tax >= SELL_TAX_WARN:
            flags.append(Flag(
                Severity.YELLOW,
                f"High sell tax ({token.sell_tax:.1f}%)",
                f"Sell tax is {token.sell_tax:.1f}%",
            ))
            risk_points += 10

    if (
        token.buy_tax is not None
        and token.sell_tax is not None
        and token.buy_tax < BUY_TAX_WARN
        and token.sell_tax < SELL_TAX_WARN
    ):
        flags.append(Flag(
            Severity.GREEN,
            f"Low taxes (buy {token.buy_tax:.1f}% / sell {token.sell_tax:.1f}%)",
            "Buy and sell taxes are within normal range",
        ))

    # --- Proxy contract ---
    if token.is_proxy is True:
        flags.append(Flag(
            Severity.YELLOW,
            "Proxy/upgradeable contract",
            "Contract can be upgraded — logic may change",
        ))
        risk_points += 5

    # --- Open source ---
    if token.is_open_source is False:
        flags.append(Flag(
            Severity.YELLOW,
            "Contract not verified",
            "Source code is not publicly verified",
        ))
        risk_points += 5

    # Clamp
    risk_score = min(100, max(0, risk_points))

    # A confirmed honeypot is critical even below the aggregate score threshold.
    if token.is_honeypot is True or risk_score >= 60:
        verdict = "HIGH RISK — Avoid"
    elif risk_score >= 30:
        verdict = "MEDIUM RISK — Proceed with caution"
    elif risk_score >= 10:
        verdict = "LOW RISK — Some concerns"
    else:
        verdict = "MINIMAL RISK — Looks clean"

    checks = (token.is_honeypot, token.is_mintable, token.is_ownership_renounced,
              token.is_lp_locked, token.top10_holder_percent, token.buy_tax, token.sell_tax)
    available = sum(value is not None for value in checks)
    if available == 0:
        verdict = "UNKNOWN — no core risk data available"
    elif available < len(checks):
        if risk_score == 0:
            verdict = "INCOMPLETE — no risk points detected in available data"
        else:
            verdict += f" (incomplete data: {available}/{len(checks)} checks)"

    return RiskReport(
        token=token,
        risk_score=risk_score,
        flags=flags,
        verdict=verdict,
    )
