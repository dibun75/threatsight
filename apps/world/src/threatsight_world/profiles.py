"""The fictional organisations the demo world can run as. Each has its own systems, agents, attacks and reviewed policy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    kind: str
    policy: str
    currency: str
    summary: str

    @property
    def organisation(self) -> str:
        return f"{self.name} (fictional)"

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "organisation": self.organisation, "kind": self.kind, "policy": self.policy,
                "currency": self.currency, "summary": self.summary}


PROFILES: dict[str, Profile] = {
    "nordvik": Profile("nordvik", "Nordvik Municipality", "Public sector", "nordvik-hardened", "NOK",
                       "A Norwegian municipality: supplier payments, citizen cases, cloud backups and case documents."),
    "helio": Profile("helio", "Helio Cloud", "Cloud and SaaS", "helio-hardened", "EUR",
                     "A European cloud company: customer refunds, tenant data, admin rights and SRE runbooks."),
}
DEFAULT = "nordvik"


def get(profile_id: str | None) -> Profile:
    profile = PROFILES.get(profile_id or DEFAULT)
    if profile is None:
        raise ValueError(f"profile must be one of {sorted(PROFILES)}")
    return profile


def policy_profile(policy: str) -> Profile | None:
    return next((p for p in PROFILES.values() if p.policy == policy), None)
