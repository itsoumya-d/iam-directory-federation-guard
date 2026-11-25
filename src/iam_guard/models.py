"""Data models for IAM Directory Federation Guard."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Optional


@dataclass(frozen=True)
class TokenClaims:
    sub: str
    iss: str
    aud: str
    exp: int
    iat: int
    nbf: Optional[int]
    roles: List[str]
    scopes: List[str]
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DirectoryUser:
    user_id: str
    username: str
    email: str
    groups: Set[str] = field(default_factory=set)
    active: bool = True
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReconciliationDiff:
    added_groups: Set[str]
    removed_groups: Set[str]
    unchanged_groups: Set[str]
    entitlements: Set[str]


@dataclass
class UserSession:
    session_id: str
    user_id: str
    created_at: int
    expires_at: int
    revoked: bool = False
