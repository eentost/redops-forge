from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit


class PolicyError(ValueError):
    """Raised when an assessment target violates the registered scope."""


def normalize_origin(url: str) -> str:
    if not isinstance(url, str) or not url or any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise PolicyError("Target URL is empty or contains whitespace/control characters.")
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise PolicyError("Target URL authority or port is invalid.") from exc

    if scheme not in {"http", "https"} or not hostname:
        raise PolicyError("Target must be an absolute HTTP(S) URL.")
    if parsed.username is not None or parsed.password is not None:
        raise PolicyError("Credentials in target URLs are not allowed.")

    hostname = hostname.rstrip(".").lower()
    if not hostname or "%" in hostname:
        raise PolicyError("Target hostname is invalid.")
    try:
        address = ipaddress.ip_address(hostname)
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        try:
            host = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise PolicyError("Target hostname is not valid IDNA.") from exc

    effective_port = port or (443 if scheme == "https" else 80)
    return f"{scheme}://{host}:{effective_port}"


def resolve_target_addresses(hostname: str, port: int) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise PolicyError("Target DNS resolution failed.") from exc

    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for record in records:
        raw = record[4][0].split("%", 1)[0]
        try:
            addresses.add(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise PolicyError("Target DNS returned an invalid address.") from exc
    if not addresses:
        raise PolicyError("Target DNS returned no usable addresses.")
    return addresses


def validate_target(target: str, allowed_targets: list[str], valid_until: str, lab_mode: bool) -> None:
    try:
        expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise PolicyError("Authorization expiry must be an ISO-8601 timestamp.") from exc
    if expiry.tzinfo is None:
        raise PolicyError("Authorization expiry must include a timezone.")
    if expiry <= datetime.now(timezone.utc):
        raise PolicyError("The authorization window has expired.")

    try:
        parsed = urlsplit(target)
        if parsed.query or parsed.fragment:
            raise PolicyError("Target URLs must not contain query strings or fragments.")
        target_origin = normalize_origin(target)
        allowed = {normalize_origin(item) for item in allowed_targets}
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise PolicyError("Target URL is invalid.") from exc

    if target_origin not in allowed:
        raise PolicyError("Target origin is not present in the approved scope.")

    addresses = resolve_target_addresses(parsed.hostname, port)
    for address in addresses:
        if lab_mode:
            if address.is_multicast or address.is_unspecified or address.is_reserved:
                raise PolicyError("Multicast, unspecified, and reserved targets are not permitted, including in lab mode.")
        elif not address.is_global:
            raise PolicyError("Non-public targets require lab_mode=true.")
