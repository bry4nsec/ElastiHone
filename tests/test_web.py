"""Tests for the FastAPI web application (sda.web.app)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sda.web.app import create_app


@pytest.fixture
def client():
    """Create a test client for the web app."""
    app = create_app()
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data


class TestInputValidation:
    def test_oversized_content_rejected(self, client):
        """Content exceeding MAX_CONTENT_LEN should be rejected."""
        huge_content = '{"name": "x"}' + ' ' * 600_000  # > 500KB
        resp = client.post(
            "/analyse",
            data={"rule_content": huge_content, "format_hint": "auto"},
        )
        assert resp.status_code == 200
        assert "too large" in resp.text


class TestIndexPage:
    def test_index_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Detection Rule Fine-Tuner" in resp.text

    def test_index_has_form(self, client):
        resp = client.get("/")
        assert 'action="/analyse"' in resp.text
        assert "rule_content" in resp.text


class TestAnalyseEndpoint:
    def test_empty_submission_shows_error(self, client):
        resp = client.post(
            "/analyse",
            data={"rule_content": "", "format_hint": "auto"},
        )
        assert resp.status_code == 200
        assert "Please provide a rule" in resp.text

    def test_whitespace_only_shows_error(self, client):
        resp = client.post(
            "/analyse",
            data={"rule_content": "   \n  ", "format_hint": "auto"},
        )
        assert resp.status_code == 200
        assert "Please provide a rule" in resp.text


class TestReportEndpoint:
    def test_missing_report_redirects(self, client):
        resp = client.get("/report/nonexistent-id")
        assert resp.status_code == 200
        assert "not found" in resp.text
