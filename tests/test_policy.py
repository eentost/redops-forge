from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import socket
import pytest
from backend.app.policy import PolicyError, normalize_origin, validate_target

def future():
    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()

def test_normalize_origin():
    assert normalize_origin("https://Example.com/path") == "https://example.com:443"

def test_scope_requires_exact_origin():
    dns=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("93.184.216.34",443))]
    with patch("backend.app.policy.socket.getaddrinfo",return_value=dns):
        with pytest.raises(PolicyError):
            validate_target("https://sub.example.com",["https://example.com"],future(),False)

def test_private_target_requires_lab_mode():
    dns=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("127.0.0.1",443))]
    with patch("backend.app.policy.socket.getaddrinfo",return_value=dns):
        with pytest.raises(PolicyError):
            validate_target("https://localhost",["https://localhost"],future(),False)
        validate_target("https://localhost",["https://localhost"],future(),True)

def test_expired_scope_is_blocked():
    expired=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
    with pytest.raises(PolicyError):
        validate_target("https://example.com",["https://example.com"],expired,False)

def test_target_query_and_fragment_are_rejected():
    with pytest.raises(PolicyError):
        validate_target("https://example.com/?token=secret",["https://example.com"],future(),False)

def test_mixed_public_and_private_dns_is_blocked():
    dns=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("93.184.216.34",443)),(socket.AF_INET,socket.SOCK_STREAM,6,"",("10.0.0.8",443))]
    with patch("backend.app.policy.socket.getaddrinfo",return_value=dns):
        with pytest.raises(PolicyError):
            validate_target("https://example.com",["https://example.com"],future(),False)

def test_trailing_dot_normalization():
    assert normalize_origin("https://EXAMPLE.com./path") == "https://example.com:443"

def test_malformed_port_is_rejected():
    with pytest.raises(PolicyError):
        normalize_origin("https://example.com:invalid")

def test_empty_dns_answer_is_rejected():
    with patch("backend.app.policy.socket.getaddrinfo",return_value=[]):
        with pytest.raises(PolicyError):
            validate_target("https://example.com",["https://example.com"],future(),False)
