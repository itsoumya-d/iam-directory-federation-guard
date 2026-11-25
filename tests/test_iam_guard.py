"""Unit tests for IAM Directory Federation Guard token validation and directory sync."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from iam_guard import (
    TokenIntrospectionGuard,
    DirectoryReconciler,
    SessionLifecycleManager,
)


def test_valid_token_introspection():
    payload = {
        "sub": "user_42",
        "iss": "https://auth.company.net",
        "aud": "cloud-api-gateway",
        "exp": 1800000000,
        "iat": 1799990000,
        "scope": "openid profile email k8s:read",
        "roles": ["PlatformAdmin", "DevOps"],
    }
    ok, msg, claims = TokenIntrospectionGuard.introspect(
        payload,
        expected_issuer="https://auth.company.net",
        expected_audience="cloud-api-gateway",
        current_time=1799995000,
        required_scopes=["openid", "k8s:read"],
    )
    assert ok is True
    assert claims.sub == "user_42"
    assert "DevOps" in claims.roles
    assert "profile" in claims.scopes


def test_expired_token_rejected():
    payload = {
        "sub": "user_42",
        "iss": "https://auth.company.net",
        "aud": "cloud-api-gateway",
        "exp": 1700000000,
        "iat": 1699990000,
    }
    ok, msg, claims = TokenIntrospectionGuard.introspect(
        payload,
        expected_issuer="https://auth.company.net",
        expected_audience="cloud-api-gateway",
        current_time=1750000000,
    )
    assert ok is False
    assert "expired" in msg.lower()
    assert claims is None


def test_issuer_and_audience_mismatch():
    payload = {
        "sub": "user_42",
        "iss": "https://untrusted-idp.org",
        "aud": "cloud-api-gateway",
        "exp": 1800000000,
    }
    ok, msg, _ = TokenIntrospectionGuard.introspect(
        payload,
        expected_issuer="https://auth.company.net",
        expected_audience="cloud-api-gateway",
        current_time=1790000000,
    )
    assert ok is False
    assert "issuer" in msg.lower()


def test_missing_required_scope():
    payload = {
        "sub": "user_42",
        "iss": "https://auth.company.net",
        "aud": "cloud-api-gateway",
        "exp": 1800000000,
        "scope": "openid profile",
    }
    ok, msg, _ = TokenIntrospectionGuard.introspect(
        payload,
        expected_issuer="https://auth.company.net",
        expected_audience="cloud-api-gateway",
        required_scopes=["openid", "k8s:write"],
        current_time=1790000000,
    )
    assert ok is False
    assert "k8s:write" in msg


def test_directory_reconciliation():
    current_groups = {"Devs", "Contractors", "Security"}
    directory_groups = {"Devs", "PlatformEngineers", "Security"}
    mapping = {
        "PlatformEngineers": "arn:aws:iam::role/PlatformAdmin",
        "Security": "arn:aws:iam::role/SecurityAuditor",
        "Devs": "arn:aws:iam::role/Developer",
    }
    diff = DirectoryReconciler.reconcile(current_groups, directory_groups, mapping)
    assert diff.added_groups == {"PlatformEngineers"}
    assert diff.removed_groups == {"Contractors"}
    assert diff.unchanged_groups == {"Devs", "Security"}
    assert "arn:aws:iam::role/PlatformAdmin" in diff.entitlements


def test_session_lifecycle_and_timeout():
    mgr = SessionLifecycleManager()
    mgr.create_session("sess-1", user_id="user_100", ttl_seconds=300, now=1000)
    assert mgr.is_valid("sess-1", now=1100) is True
    assert mgr.is_valid("sess-1", now=1350) is False  # expired (1000 + 300 = 1300)


def test_backchannel_logout():
    mgr = SessionLifecycleManager()
    mgr.create_session("sess-1", user_id="user_200", ttl_seconds=3600, now=1000)
    mgr.create_session("sess-2", user_id="user_200", ttl_seconds=3600, now=1050)
    mgr.create_session("sess-3", user_id="user_300", ttl_seconds=3600, now=1000)

    revoked = mgr.backchannel_logout("user_200")
    assert revoked == 2
    assert mgr.is_valid("sess-1", now=1100) is False
    assert mgr.is_valid("sess-2", now=1100) is False
    assert mgr.is_valid("sess-3", now=1100) is True  # user_300 session untouched
