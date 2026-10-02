"""honeypot.is API provider.

Docs: https://honeypot.is/
Free, no API key required. EVM chains only.
"""

from __future__ import annotations

import httpx

from scanner.models import TokenInfo
from scanner.providers import TokenProvider

HONEYPOT_BASE = "https://api.honeypot.is/v2"

# Supported chains (by chain ID)
CHAIN_MAP = {
    "ethereum": "1",
    "eth": "1",
    "bsc": "56",
    "polygon": "137",
    "arbitrum": "42161",
    "optimism": "10",
    "base": "8453",
    "avalanche": "43114",
}


class HoneypotProvider(TokenProvider):
    """honeypot.is — buy/sell simulation for EVM tokens."""

    def __init__(self, timeout: float = 15.0, retries: int = 2):
        self._timeout = timeout
        self._retries = retries

    @property
    def name(self) -> str:
        return "honeypot.is"

    async def get_token_info(self, chain: str, address: str) -> TokenInfo:
        chain_lower = chain.lower()

        if chain_lower in ("solana", "sol"):
            # honeypot.is doesn't support Solana
            return TokenInfo(chain=chain, address=address)

        chain_id = CHAIN_MAP.get(chain_lower, chain_lower)
        url = f"{HONEYPOT_BASE}/IsHoneypot"
        params = {"address": address, "chainID": chain_id}

        data = await self._request(url, params)

        honeypot_result = data.get("honeypotResult", {})
        token_data = data.get("token", {})
        sim_result = data.get("simulationResult", {})

        buy_tax = None
        sell_tax = None
        if sim_result:
            buy_tax = sim_result.get("buyTax")
            sell_tax = sim_result.get("sellTax")

        return TokenInfo(
            chain=chain,
            address=address,
            name=token_data.get("name"),
            symbol=token_data.get("symbol"),
            is_honeypot=honeypot_result.get("isHoneypot"),
            honeypot_reason=honeypot_result.get("honeypotReason"),
            buy_tax=buy_tax,
            sell_tax=sell_tax,
            total_supply=str(token_data.get("totalSupply")) if token_data.get("totalSupply") else None,
            holder_count=token_data.get("totalHolders"),
        )

    async def _request(self, url: str, params: dict) -> dict:
        last_err = None
        for attempt in range(self._retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.get(url, params=params)
                    resp.raise_for_status()
                    return resp.json()
            except httpx.HTTPError as e:
                last_err = e
                if attempt < self._retries:
                    import asyncio
                    await asyncio.sleep(1 * (attempt + 1))
        raise RuntimeError(f"honeypot.is API failed after {self._retries + 1} attempts: {last_err}")
