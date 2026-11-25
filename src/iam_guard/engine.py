"""Token introspection, directory reconciliation, and session state engines."""
from __future__ import annotations
import time
from typing import Dict, Any, List, Set, Optional, Tuple
from iam_guard.models import TokenClaims, DirectoryUser, ReconciliationDiff, UserSession


class TokenIntrospectionGuard:
    """Validates claims and token integrity according to OIDC / OAuth 2.0 standards."""

    @staticmethod
    def introspect(
        claims_dict: Dict[str, Any],
        expected_issuer: str,
        expected_audience: str,
        current_time: Optional[int] = None,
        required_scopes: Optional[List[str]] = None,
        leeway_seconds: int = 60,
    ) -> Tuple[bool, str, Optional[TokenClaims]]:
        now = int(time.time()) if current_time is None else current_time

        # Validate issuer
        iss = claims_dict.get("iss")
        if iss != expected_issuer:
            return False, f"Invalid issuer: expected '{expected_issuer}', got '{iss}'", None

        # Validate audience
        aud = claims_dict.get("aud")
        if aud != expected_audience:
            return False, f"Invalid audience: expected '{expected_audience}', got '{aud}'", None

        # Validate subject
        sub = claims_dict.get("sub")
        if not sub or not isinstance(sub, str):
            return False, "Missing or invalid 'sub' claim", None

        # Validate expiration
        exp = claims_dict.get("exp")
        if exp is None or not isinstance(exp, (int, float)):
            return False, "Missing or non-numeric 'exp' claim", None
        if now > (exp + leeway_seconds):
            return False, f"Token expired at {exp} (current time {now})", None

        # Validate Not Before (nbf)
        nbf = claims_dict.get("nbf")
        if nbf is not None and isinstance(nbf, (int, float)):
            if now < (nbf - leeway_seconds):
                return False, f"Token not valid before {nbf} (current time {now})", None

        # Validate scopes
        raw_scopes = claims_dict.get("scope") or claims_dict.get("scopes") or []
        if isinstance(raw_scopes, str):
            token_scopes = raw_scopes.split()
        elif isinstance(raw_scopes, list):
            token_scopes = [str(s) for s in raw_scopes]
        else:
            token_scopes = []

        if required_scopes:
            missing = set(required_scopes) - set(token_scopes)
            if missing:
                return False, f"Missing required scopes: {sorted(list(missing))}", None

        # Extract roles
        raw_roles = claims_dict.get("roles") or claims_dict.get("groups") or []
        roles = [str(r) for r in raw_roles] if isinstance(raw_roles, list) else []

        claims = TokenClaims(
            sub=sub,
            iss=iss,
            aud=aud,
            exp=int(exp),
            iat=int(claims_dict.get("iat", now)),
            nbf=int(nbf) if nbf is not None else None,
            roles=roles,
            scopes=token_scopes,
            extra={k: v for k, v in claims_dict.items() if k not in ("sub", "iss", "aud", "exp", "iat", "nbf", "scope", "scopes", "roles", "groups")},
        )
        return True, "Token valid", claims


class DirectoryReconciler:
    """Reconciles enterprise directory groups with cloud workload entitlements."""

    @staticmethod
    def reconcile(
        current_groups: Set[str],
        directory_groups: Set[str],
        role_entitlement_map: Dict[str, str],
    ) -> ReconciliationDiff:
        added = directory_groups - current_groups
        removed = current_groups - directory_groups
        unchanged = current_groups & directory_groups

        entitlements = set()
        for group in directory_groups:
            if group in role_entitlement_map:
                entitlements.add(role_entitlement_map[group])

        return ReconciliationDiff(
            added_groups=added,
            removed_groups=removed,
            unchanged_groups=unchanged,
            entitlements=entitlements,
        )


class SessionLifecycleManager:
    """Manages SSO session state, idle expiration, and backchannel logout fan-out."""

    def __init__(self):
        self._sessions: Dict[str, UserSession] = {}

    def create_session(
        self,
        session_id: str,
        user_id: str,
        ttl_seconds: int = 3600,
        now: Optional[int] = None,
    ) -> UserSession:
        t = int(time.time()) if now is None else now
        session = UserSession(
            session_id=session_id,
            user_id=user_id,
            created_at=t,
            expires_at=t + ttl_seconds,
            revoked=False,
        )
        self._sessions[session_id] = session
        return session

    def is_valid(self, session_id: str, now: Optional[int] = None) -> bool:
        session = self._sessions.get(session_id)
        if not session or session.revoked:
            return False
        t = int(time.time()) if now is None else now
        return t <= session.expires_at

    def revoke_session(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if not session:
            return False
        session.revoked = True
        return True

    def backchannel_logout(self, user_id: str) -> int:
        revoked_count = 0
        for session in self._sessions.values():
            if session.user_id == user_id and not session.revoked:
                session.revoked = True
                revoked_count += 1
        return revoked_count
