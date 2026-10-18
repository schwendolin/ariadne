"""Anfrage-Modelle der API v2 (``docs/web-api.md``). Unbekannte Felder ergeben 422 (``extra =
"forbid"``), Typen werden nicht umgedeutet (``strict``: ``"10"`` ist keine Zahl)."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ariadne.events import StageKind

__all__ = [
    "PauseRequest",
    "PresentationRequest",
    "ContextOp",
    "SetOp",
    "PushOp",
    "PopOp",
    "AcceptOp",
    "DecisionInput",
    "DecisionRequest",
    "ConfirmGroupRequest",
    "RevealRequest",
    "RevealInput",
    "RevealClaim",
    "Position",
    "PositionsRequest",
    "MAX_WEB_PAUSE_MIN",
    "PrefsRequest",
    "SeenRequest",
    "ScopeAckRequest",
    "Theme",
    "Density",
]

MAX_WEB_PAUSE_MIN = 30  # länger nur im Terminal (Briefing 9.10, Vertrag 1.4 Punkt 5)
INT64_MAX = 2**63 - 1  # grösste Ganzzahl, die SQLite und das Journal speichern (SEC-W5)


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class PauseRequest(_In):
    minutes: int | None = Field(default=None, ge=1, le=240)


class PresentationRequest(_In):
    on: bool


_Host = Annotated[str, Field(min_length=1, max_length=253)]
_User = Annotated[str, Field(min_length=1, max_length=64)]


class SetOp(_In):
    op: Literal["set"]
    host: _Host | None = None
    user: _User | None = None
    kind: StageKind | None = None
    from_off: int | None = Field(default=None, ge=0, le=INT64_MAX)


class PushOp(_In):
    op: Literal["push"]
    kind: StageKind | None = None
    host: _Host | None = None
    user: _User | None = None


class PopOp(_In):
    op: Literal["pop"]


class AcceptOp(_In):
    op: Literal["accept"]
    item_key: str = Field(min_length=1, max_length=300)


ContextOp = Annotated[SetOp | PushOp | PopOp | AcceptOp, Field(discriminator="op")]


class DecisionInput(_In):
    kind: str = Field(min_length=1, max_length=64)
    payload: dict[str, Any]
    client_ref: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


class DecisionRequest(_In):
    decisions: list[DecisionInput] = Field(min_length=1, max_length=500)


class ConfirmGroupRequest(_In):
    group_ref: str = Field(pattern=r"^g[0-9a-f]{8}$")


class RevealInput(_In):
    ref: Literal["input"]
    seq: int = Field(ge=1, le=INT64_MAX)


class RevealClaim(_In):
    ref: Literal["claim"]
    claim_key: str = Field(pattern=r"^[0-9a-f]{64}$")


RevealRequest = Annotated[RevealInput | RevealClaim, Field(discriminator="ref")]


class Position(_In):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)

    x: float = Field(ge=-1e9, le=1e9)
    y: float = Field(ge=-1e9, le=1e9)


class PositionsRequest(_In):
    positions: dict[Annotated[str, Field(min_length=1, max_length=512)], Position] = Field(max_length=5000)


# --------------------------------------------------------------------------- Bau v0.1-Oberfläche (18)

Theme = Literal["system", "light", "dark"]
Density = Literal["comfortable", "compact"]


class PrefsRequest(_In):
    """``PUT /ui/prefs`` (18.2): nur die genannten Felder; ``null`` gilt nicht als Wert."""

    theme: Theme | None = None
    density: Density | None = None
    learning: bool | None = None


class SeenRequest(_In):
    """``PUT /p/{pid}/ui/seen`` (18.3): leerer Körper; die Zeit nimmt der Server selbst."""


class ScopeAckRequest(_In):
    """``PUT /p/{pid}/ui/scope-ack`` (18.4): Befehl voll (``<tid>@<off>``) oder als ``cmd_ref``."""

    cmd_id: str = Field(min_length=10, max_length=200, pattern=r"^[0-9A-Za-z-]{8,64}@[0-9]{1,19}$")
