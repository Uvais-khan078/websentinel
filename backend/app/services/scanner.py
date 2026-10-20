"""Safe, single-page security-header scanner for the authorized Juice Shop lab."""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from requests.exceptions import RequestException


DEFAULT_TARGET = "http://127.0.0.1:3000"
REQUEST_TIMEOUT = (2.0, 4.0)
MAX_REQUESTS = 4
MAX_REDIRECTS = 3
MIN_REQUEST_INTERVAL = 0.25


class InvalidTarget(ValueError):
    """Target is outside the explicitly authorized local lab scope."""


class ScanNetworkError(RuntimeError):
    """The target could not be safely reached."""


@dataclass(frozen=True)
class ScanObservation:
    url: str
    status_code: int
    headers: dict[str, str]
    content_type: str | None
    content_length: int | None


@dataclass(frozen=True)
class ScannerFinding:
    title: str
    vulnerability_type: str
    severity: str
    url: str
    description: str
    evidence: str
    remediation: str


def validate_target(url: str) -> str:
    if not isinstance(url, str) or len(url) > 500 or any(ord(c) < 32 for c in url):
        raise InvalidTarget("Target URL is invalid")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise InvalidTarget("Target URL is invalid") from exc
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise InvalidTarget("Only an HTTP URL to the authorized local lab is allowed")
    if parsed.hostname is None or port != 3000:
        raise InvalidTarget("Target must use the authorized local lab on port 3000")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost":
        pass
    else:
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise InvalidTarget("Only loopback targets are authorized")
        except ValueError as exc:
            raise InvalidTarget("Only loopback targets are authorized") from exc
    if parsed.path and not parsed.path.startswith("/"):
        raise InvalidTarget("Target path is invalid")
    # Normalize away fragments/query while preserving a configured base path.
    return urlunsplit(("http", parsed.netloc, parsed.path or "/", "", ""))


def _resolve_all_loopback(host: str) -> bool:
    try:
        return all(ipaddress.ip_address(item[4][0]).is_loopback
                   for item in socket.getaddrinfo(host, 3000, type=socket.SOCK_STREAM))
    except (OSError, ValueError):
        return False


def fetch_target(url: str) -> ScanObservation:
    current = validate_target(url)
    request_count = 0
    last_request = 0.0
    session = requests.Session()
    session.trust_env = False
    try:
        for redirect_count in range(MAX_REDIRECTS + 1):
            parsed = urlsplit(current)
            host = parsed.hostname or ""
            if not _resolve_all_loopback(host):
                raise InvalidTarget("Target must resolve only to loopback addresses")
            if request_count >= MAX_REQUESTS:
                raise ScanNetworkError("Request cap reached")
            delay = MIN_REQUEST_INTERVAL - (time.monotonic() - last_request)
            if delay > 0:
                time.sleep(delay)
            request_count += 1
            try:
                response = session.get(current, timeout=REQUEST_TIMEOUT, allow_redirects=False,
                                       stream=True, headers={"User-Agent": "WebSentinel-MVP/0.1"})
            except RequestException as exc:
                raise ScanNetworkError("Target request failed") from exc
            last_request = time.monotonic()
            if response.is_redirect or response.is_permanent_redirect or response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                response.close()
                if not location or redirect_count >= MAX_REDIRECTS:
                    raise ScanNetworkError("Redirect limit reached or missing Location")
                next_url = urljoin(current, location)
                # Validate before making any request to the redirect destination.
                current = validate_target(next_url)
                continue
            safe_headers = {key: value for key, value in response.headers.items()
                            if key.lower() in {"content-security-policy", "x-content-type-options",
                                               "x-frame-options", "referrer-policy", "content-type",
                                               "content-length"}}
            try:
                length = int(response.headers["Content-Length"]) if response.headers.get("Content-Length", "").isdigit() else None
            except (ValueError, TypeError):
                length = None
            observation = ScanObservation(current, response.status_code, safe_headers,
                                          response.headers.get("Content-Type"), length)
            response.close()
            return observation
        raise ScanNetworkError("Redirect limit reached")
    finally:
        session.close()


def check_headers(observation: ScanObservation) -> list[ScannerFinding]:
    headers = {key.lower(): value for key, value in observation.headers.items()}
    checks = [
        ("Content-Security-Policy", "Missing Content-Security-Policy", "MissingSecurityHeader", "medium",
         "The response does not include a Content-Security-Policy header, reducing browser-side restrictions on resource loading and script execution.",
         "Send a restrictive Content-Security-Policy appropriate to the application and test it in report-only mode before enforcement.", "CSP"),
        ("X-Content-Type-Options", "Missing X-Content-Type-Options", "MissingSecurityHeader", "low",
         "The response does not instruct browsers to avoid MIME type sniffing.",
         "Set X-Content-Type-Options: nosniff on application responses.", "X-Content-Type-Options"),
        ("X-Frame-Options", "Missing X-Frame-Options", "MissingSecurityHeader", "low",
         "The response does not include a legacy frame embedding restriction.",
         "Set X-Frame-Options to DENY or SAMEORIGIN, and use CSP frame-ancestors for modern browsers.", "X-Frame-Options"),
        ("Referrer-Policy", "Missing Referrer-Policy", "MissingSecurityHeader", "low",
         "The response does not declare how much referrer information browsers should send.",
         "Set a Referrer-Policy such as strict-origin-when-cross-origin.", "Referrer-Policy"),
    ]
    findings = []
    for header, title, kind, severity, description, remediation, evidence_header in checks:
        value = headers.get(header.lower())
        if value is None:
            evidence = f"HTTP {observation.status_code}; {evidence_header} header absent"
            findings.append(ScannerFinding(title, kind, severity, observation.url, description, evidence, remediation))
    return findings


def scan(url: str) -> tuple[ScanObservation, list[ScannerFinding]]:
    observation = fetch_target(url)
    return observation, check_headers(observation)
