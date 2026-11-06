from datetime import datetime, timezone
from urllib.parse import urlparse
import ipaddress
import socket


class PolicyError(ValueError):
    pass


def normalize_origin(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PolicyError("Target must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password:
        raise PolicyError("Credentials in target URLs are not allowed.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise PolicyError("Target port is invalid.") from exc
    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}:{port}"


def validate_target(target: str, allowed_targets: list[str], valid_until: str, lab_mode: bool) -> None:
    try:
        expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyError("Authorization expiry must be an ISO-8601 timestamp.") from exc
    if expiry.tzinfo is None:
        raise PolicyError("Authorization expiry must include a timezone.")
    if expiry <= datetime.now(timezone.utc):
        raise PolicyError("The authorization window has expired.")
    parsed_target = urlparse(target)
    if parsed_target.query or parsed_target.fragment:
        raise PolicyError("Target URLs must not contain query strings or fragments.")
    target_origin = normalize_origin(target)
    allowed = {normalize_origin(item) for item in allowed_targets}
    if target_origin not in allowed:
        raise PolicyError("Target origin is not present in the approved scope.")
    parsed = urlparse(target)
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)}
    except (socket.gaierror, UnicodeError) as exc:
        raise PolicyError("Target DNS resolution failed.") from exc
    for raw in addresses:
        ip = ipaddress.ip_address(raw)
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast) and not lab_mode:
            raise PolicyError("Private, loopback, link-local, reserved and multicast targets require lab_mode=true.")
