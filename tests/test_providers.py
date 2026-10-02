import asyncio

import pytest

from scanner.analyze import _merge_token_info, analyze_token
from scanner.models import TokenInfo
from scanner.providers.goplus import GoPlusProvider, _parse_bool


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1])
def test_invalid_percentages_cannot_be_scored_as_clean(value):
    with pytest.raises(ValueError):
        TokenInfo(chain="eth", address="x", buy_tax=value)


def test_invalid_boolean_signal_is_not_counted_as_known():
    with pytest.raises(ValueError):
        TokenInfo(chain="eth", address="x", is_honeypot="unknown")


@pytest.mark.parametrize("value, expected", [("1", True), ("0", False), (True, True),
                                            (False, False), ("", None), ("unknown", None)])
def test_bool_unknown_is_not_false(value, expected):
    assert _parse_bool(value) is expected


@pytest.mark.parametrize("owner, reclaim, expected", [
    ("0x1234", "0", False), ("0x" + "0" * 40, "0", True),
    ("", "0", True), ("0x" + "0" * 40, "1", False), (None, "0", None)])
def test_evm_owner_semantics_and_zero_taxes(monkeypatch, owner, reclaim, expected):
    provider = GoPlusProvider()
    async def request(*args):
        return {"result": {"0x1234": {"owner_address": owner, "can_take_back_ownership": reclaim,
                                      "buy_tax": 0, "sell_tax": "0", "is_honeypot": ""}}}
    monkeypatch.setattr(provider, "_request", request)
    info = asyncio.run(provider.get_token_info("eth", "0x1234"))
    assert info.is_ownership_renounced is expected
    assert info.buy_tax == info.sell_tax == 0
    assert info.is_honeypot is None


def test_solana_nested_mint_status(monkeypatch):
    provider = GoPlusProvider()
    async def request(*args):
        return {"result": {"mint": {"metadata": {"name": "Test", "symbol": "T"},
                                   "mintable": {"status": "1"}, "holders": [{"percent": "0.2"}]}}}
    monkeypatch.setattr(provider, "_request", request)
    info = asyncio.run(provider.get_token_info("sol", "mint"))
    assert info.is_mintable is True
    assert info.name == "Test" and info.top10_holder_percent == 20
    assert info.is_ownership_renounced is None


def test_provider_conflicts_preserve_adverse_signals():
    primary = TokenInfo(chain="eth", address="x", is_honeypot=False, is_mintable=False,
                        is_ownership_renounced=True, buy_tax=1)
    other = TokenInfo(chain="eth", address="x", is_honeypot=True, is_mintable=True,
                      is_ownership_renounced=False, buy_tax=20)
    merged = _merge_token_info(primary, other)
    assert merged.is_honeypot and merged.is_mintable
    assert merged.is_ownership_renounced is False and merged.buy_tax == 20


def test_empty_provider_and_partial_failure_are_visible():
    class EmptyProvider:
        name = "empty"
        async def get_token_info(self, chain, address):
            return TokenInfo(chain=chain, address=address)
    class FailedProvider:
        name = "failed"
        async def get_token_info(self, chain, address):
            raise RuntimeError("offline")
    report = asyncio.run(analyze_token("eth", "x", [EmptyProvider(), FailedProvider()]))
    assert report.verdict.startswith("UNKNOWN")
    assert report.data_sources == []
    assert report.data_errors == ["failed: offline"]
