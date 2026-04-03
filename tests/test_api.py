import pytest
from fastapi.testclient import TestClient
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.main import app

client = TestClient(app)

DEMO_API_KEY = "phishdetect-api-key-demo-2024"

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_scan_requires_auth():
    response = client.post("/scan-url", json={"url": "http://google.com"})
    assert response.status_code == 401

def test_scan_with_api_key():
    response = client.post(
        "/scan-url",
        json={"url": "https://www.google.com"},
        headers={"X-Api-Key": DEMO_API_KEY}
    )
    assert response.status_code == 200
    data = response.json()
    assert "result" in data
    assert data["result"] in ["Safe", "Phishing"]
    assert 0.0 <= data["risk_score"] <= 1.0

def test_phishing_url_detected():
    phishing_url = "http://paypal-secure-login.verify-account.com:8080/update?token=abc"
    response = client.post(
        "/scan-url",
        json={"url": phishing_url},
        headers={"X-Api-Key": DEMO_API_KEY}
    )
    assert response.status_code == 200
    assert response.json()["risk_score"] > 0.3

def test_stats_endpoint():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "phishing_count" in data
    assert "safe_count" in data