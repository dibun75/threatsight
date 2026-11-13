from __future__ import annotations

from threatsight_api.config import Settings
from threatsight_api.intelligence.providers.base import ExtractionProvider
from threatsight_api.intelligence.providers.heuristic import HeuristicProvider
from threatsight_api.intelligence.providers.openai import OpenAIProvider


def get_extraction_provider(settings: Settings | None = None) -> ExtractionProvider:
    from threatsight_api.config import get_settings

    cfg = settings or get_settings()
    name = cfg.extraction_provider.strip().lower()
    if name == "heuristic":
        return HeuristicProvider()
    if name == "openai":
        return OpenAIProvider(
            api_key=cfg.openai_api_key,
            model=cfg.openai_model,
            base_url=cfg.openai_base_url,
        )
    raise ValueError(f"Unknown extraction provider: {cfg.extraction_provider}")
