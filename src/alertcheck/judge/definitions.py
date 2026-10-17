"""IPA item definitions used by the judge (design §8.1)."""

from __future__ import annotations

from functools import cache
from importlib.resources import files

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from alertcheck.core.models import IPA_ITEMS


class ItemDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    category: str
    requires_coverage: list[str] = Field(default_factory=list)
    questions: list[str] = Field(default_factory=list)


class Definitions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    categories: dict[str, str]
    items: dict[str, ItemDefinition]
    input_hints: dict[str, str] = Field(default_factory=dict)

    @field_validator("items")
    @classmethod
    def _all_items(cls, items: dict[str, ItemDefinition]) -> dict[str, ItemDefinition]:
        missing, unknown = IPA_ITEMS - set(items), set(items) - IPA_ITEMS
        if missing or unknown:
            raise ValueError(f"missing items {sorted(missing)}, unknown items {sorted(unknown)}")
        return items

    @model_validator(mode="after")
    def _known_categories(self) -> Definitions:
        for item_id, item in self.items.items():
            if item.category not in self.categories:
                raise ValueError(f"{item_id}: unknown category {item.category!r}")
        return self


@cache
def load_definitions() -> Definitions:
    raw = files("alertcheck.judge").joinpath("ipa_items.yaml").read_text(encoding="utf-8")
    return Definitions.model_validate(yaml.safe_load(raw))
