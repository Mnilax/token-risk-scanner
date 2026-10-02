"""Data models for token risk analysis."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    RED = "red"
    YELLOW = "yellow"
    GREEN = "green"


@dataclass
class Flag:
    """A single risk flag."""

    severity: Severity
    label: str
    detail: str


@dataclass
class TokenInfo:
    """Raw token information from providers."""

    chain: str
    address: str
    name: str | None = None
    symbol: str | None = None

    # Honeypot
    is_honeypot: bool | None = None
    honeypot_reason: str | None = None

    # Mint authority
    is_mintable: bool | None = None

    # Ownership
    is_ownership_renounced: bool | None = None
    owner_address: str | None = None

    # LP
    is_lp_locked: bool | None = None
    lp_lock_percent: float | None = None

    # Holders
    top10_holder_percent: float | None = None
    holder_count: int | None = None

    # Tax
    buy_tax: float | None = None  # percentage 0-100
    sell_tax: float | None = None  # percentage 0-100

    # Proxy / upgradeable
    is_proxy: bool | None = None
    is_open_source: bool | None = None

    # Extra
    total_supply: str | None = None
    creator_address: str | None = None

    def __post_init__(self) -> None:
        for name in ("is_honeypot", "is_mintable", "is_ownership_renounced", "is_lp_locked",
                     "is_proxy", "is_open_source"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, bool):
                raise ValueError(f"{name} must be boolean or unknown")
        for name in ("lp_lock_percent", "top10_holder_percent", "buy_tax", "sell_tax"):
            value = getattr(self, name)
            if value is not None and (not math.isfinite(value) or value < 0):
                raise ValueError(f"{name} must be finite and nonnegative")


@dataclass
class RiskReport:
    """Final risk assessment for a token."""

    token: TokenInfo
    risk_score: int  # 0-100, higher = riskier
    flags: list[Flag] = field(default_factory=list)
    verdict: str = ""
    data_sources: list[str] = field(default_factory=list)
    data_errors: list[str] = field(default_factory=list)
