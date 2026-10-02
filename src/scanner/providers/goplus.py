"""GoPlus Security API provider.

Docs: https://docs.gopluslabs.io/
Free tier, no API key required for basic queries.
Supports EVM chains and Solana.
"""

from __future__ import annotations

import httpx

from scanner.models import TokenInfo
from scanner.providers import TokenProvider

# GoPlus chain IDs
CHAIN_MAP = {
    "ethereum": "1",
    "eth": "1",
    "bsc": "56",
    "polygon": "137",
    "arbitrum": "42161",
    "optimism": "10",
    "avalanche": "43114",
    "base": "8453",
    "solana": "solana",
    "sol": "solana",
}

GOPLUS_BASE = "https://api.gopluslabs.io/api/v1"


def _parse_bool(val: str | int | None) -> bool | None:
    """GoPlus returns '1'/'0' strings for booleans."""
    if val is True or val == "1" or val == 1:
        return True
    if val is False or val == "0" or val == 0:
        return False
    return None


def _ownership_renounced(info: dict) -> bool | None:
    # Reclaimability is a separate privilege, not proof that an active owner resigned.
    if _parse_bool(info.get("can_take_back_ownership")) or _parse_bool(info.get("hidden_owner")):
        return False
    owner = info.get("owner_address")
    if owner is None:
        return None
    return owner.lower() in ("", "0x0000000000000000000000000000000000000000",
                             "0x000000000000000000000000000000000000dead")


class GoPlusProvider(TokenProvider):
    """GoPlus Security API — free tier, no key needed."""

    def __init__(self, timeout: float = 15.0, retries: int = 2):
        self._timeout = timeout
        self._retries = retries

    @property
    def name(self) -> str:
        return "GoPlus Security"

    async def get_token_info(self, chain: str, address: str) -> TokenInfo:
        chain_lower = chain.lower()
        chain_id = CHAIN_MAP.get(chain_lower, chain_lower)

        if chain_id == "solana":
            return await self._fetch_solana(address)
        return await self._fetch_evm(chain_id, address, chain_lower)

    async def _fetch_evm(self, chain_id: str, address: str, chain: str) -> TokenInfo:
        url = f"{GOPLUS_BASE}/token_security/{chain_id}"
        params = {"contract_addresses": address.lower()}

        data = await self._request(url, params)
        result = data.get("result", {})
        info = result.get(address.lower(), {})

        if not info:
            return TokenInfo(chain=chain, address=address)

        # Parse holder concentration
        holders = info.get("holders", [])
        top10_pct = None
        if holders:
            top10 = holders[:10]
            top10_pct = sum(float(h.get("percent", 0)) * 100 for h in top10)

        return TokenInfo(
            chain=chain,
            address=address,
            name=info.get("token_name"),
            symbol=info.get("token_symbol"),
            is_honeypot=_parse_bool(info.get("is_honeypot")),
            honeypot_reason="Same creator deployed honeypots" if _parse_bool(info.get("honeypot_with_same_creator")) else None,
            is_mintable=_parse_bool(info.get("is_mintable")),
            is_ownership_renounced=_ownership_renounced(info),
            owner_address=info.get("owner_address"),
            is_lp_locked=None,  # Requires separate LP check
            top10_holder_percent=top10_pct,
            holder_count=int(info["holder_count"]) if info.get("holder_count") else None,
            buy_tax=float(info["buy_tax"]) * 100 if info.get("buy_tax") not in (None, "") else None,
            sell_tax=float(info["sell_tax"]) * 100 if info.get("sell_tax") not in (None, "") else None,
            is_proxy=_parse_bool(info.get("is_proxy")),
            is_open_source=_parse_bool(info.get("is_open_source")),
            total_supply=info.get("total_supply"),
            creator_address=info.get("creator_address"),
        )

    async def _fetch_solana(self, address: str) -> TokenInfo:
        url = f"{GOPLUS_BASE}/solana/token_security"
        params = {"contract_addresses": address}

        data = await self._request(url, params)
        result = data.get("result", {})
        info = result.get(address, {})

        if not info:
            return TokenInfo(chain="solana", address=address)

        metadata = info.get("metadata", {})
        name = info.get("name")
        if isinstance(name, dict):
            metadata = name
            name = metadata.get("name")
        mintable = info.get("mintable")
        if isinstance(mintable, dict):
            mintable = mintable.get("status")
        holders = info.get("holders", [])
        top10_pct = sum(float(h.get("percent", 0)) * 100 for h in holders[:10]) if holders else None
        return TokenInfo(
            chain="solana",
            address=address,
            name=name or info.get("token_name") or metadata.get("name"),
            symbol=info.get("symbol") or info.get("token_symbol") or metadata.get("symbol"),
            is_mintable=_parse_bool(mintable),
            top10_holder_percent=top10_pct,
            holder_count=int(info["holder_count"]) if info.get("holder_count") else None,
            total_supply=info.get("total_supply"),
            creator_address=info.get("creator") or info.get("creator_address"),
        )

    async def _request(self, url: str, params: dict) -> dict:
        last_err = None
        for attempt in range(self._retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.get(url, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                    if data.get("code") != 1:
                        raise ValueError(f"GoPlus API error: {data.get('message', 'unknown')}")
                    return data
            except (httpx.HTTPError, ValueError) as e:
                last_err = e
                if attempt < self._retries:
                    import asyncio
                    await asyncio.sleep(1 * (attempt + 1))
        raise RuntimeError(f"GoPlus API failed after {self._retries + 1} attempts: {last_err}")
