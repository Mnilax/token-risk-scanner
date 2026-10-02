"""Normalize and merge data from multiple providers into a single RiskReport."""

from __future__ import annotations

import asyncio

from scanner.models import RiskReport, TokenInfo
from scanner.providers import TokenProvider
from scanner.providers.goplus import GoPlusProvider
from scanner.providers.honeypot import HoneypotProvider
from scanner.score import score_token


def _merge_token_info(primary: TokenInfo, *others: TokenInfo) -> TokenInfo:
    """Fill missing data and conservatively preserve adverse provider signals."""
    adverse_true = {"is_honeypot", "is_mintable", "is_proxy"}
    adverse_false = {"is_ownership_renounced", "is_lp_locked", "is_open_source"}
    higher_risk = {"buy_tax", "sell_tax", "top10_holder_percent"}
    for other in others:
        for field_name in TokenInfo.__dataclass_fields__:
            if field_name in ("chain", "address"):
                continue
            primary_val = getattr(primary, field_name)
            other_val = getattr(other, field_name)
            if primary_val is None and other_val is not None:
                setattr(primary, field_name, other_val)
            elif field_name in adverse_true and other_val is True:
                setattr(primary, field_name, True)
            elif field_name in adverse_false and other_val is False:
                setattr(primary, field_name, False)
            elif field_name in higher_risk and other_val is not None:
                setattr(primary, field_name, max(primary_val, other_val))
            elif field_name == "lp_lock_percent" and other_val is not None:
                setattr(primary, field_name, min(primary_val, other_val))
    return primary


async def analyze_token(
    chain: str,
    address: str,
    providers: list[TokenProvider] | None = None,
) -> RiskReport:
    """Fetch data from all providers, merge, and score."""
    if providers is None:
        providers = [GoPlusProvider(), HoneypotProvider()]

    results: list[TokenInfo] = []
    source_names: list[str] = []
    errors: list[str] = []

    for provider in providers:
        try:
            info = await provider.get_token_info(chain, address)
            results.append(info)
            if any(getattr(info, name) is not None for name in TokenInfo.__dataclass_fields__
                   if name not in ("chain", "address")):
                source_names.append(provider.name)
        except Exception as e:  # noqa: BLE001 - Isolate failures from pluggable providers.
            errors.append(f"{provider.name}: {e}")

    if not results:
        # All providers failed — return empty report
        token = TokenInfo(chain=chain, address=address)
        report = score_token(token)
        report.verdict = f"UNKNOWN — all data sources failed: {'; '.join(errors)}"
        report.data_errors = errors
        return report

    # Merge: first result is primary, rest fill gaps
    merged = _merge_token_info(results[0], *results[1:])

    report = score_token(merged)
    report.data_sources = source_names
    report.data_errors = errors
    return report


def analyze_token_sync(chain: str, address: str) -> RiskReport:
    """Synchronous wrapper for analyze_token."""
    return asyncio.run(analyze_token(chain, address))
