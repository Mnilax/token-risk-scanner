"""Data providers for token information."""

from __future__ import annotations

from abc import ABC, abstractmethod

from scanner.models import TokenInfo


class TokenProvider(ABC):
    """Abstract interface for token data providers."""

    @abstractmethod
    async def get_token_info(self, chain: str, address: str) -> TokenInfo:
        """Fetch token information for a given chain and address."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for attribution."""
        ...
