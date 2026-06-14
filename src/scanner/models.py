"""Data models for token risk analysis."""

from __future__ import annotations

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


@dataclass
class RiskReport:
    """Final risk assessment for a token."""

    token: TokenInfo
    risk_score: int  # 0-100, higher = riskier
    flags: list[Flag] = field(default_factory=list)
    verdict: str = ""
    data_sources: list[str] = field(default_factory=list)
