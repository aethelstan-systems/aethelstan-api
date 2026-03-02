# engine.py — Aethelstan Structural Resolution Diagnostic v4.1 (Hardened API Core)
#
# Refactor notes (from v4.0):
# - No CLI / sys.argv / input()
# - No global DOMAIN
# - No print()
# - Strict domain canonicalisation
# - DNS resolution + private/reserved IP blocking (SSRF guard)
# - Same-host crawl scope only
# - Hard caps: pages + depth + bytes + timeouts
# - Structured JSON return (API-safe)
#
# Public entry point:
#   run_scan(domain: str) -> dict

from __future__ import annotations

import json
import socket
import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag


ENGINE_VERSION = "4.1"

# Hardened crawl limits (v1 defaults)
MAX_PAGES = 25
MAX_DEPTH = 2
REQUEST_TIMEOUT = 5  # seconds
MAX_BYTES = 1_000_000  # 1MB cap per page

WEIGHTS = {
    "ENTITY EXPLICITNESS": 0.25,
    "IDENTIFIER STABILITY": 0.15,
    "STRUCTURAL GRAPH INTEGRITY": 0.15,
    "HIERARCHICAL CLARITY": 0.10,
    "SURFACE COHERENCE": 0.10,
    "ENTITY RESOLUTION INTENSITY": 0.25,
}


# ------------------------------------------------------------
# DOMAIN / HOST VALIDATION (SSRF GUARD)
# ------------------------------------------------------------

def canonicalise_domain(domain: str) -> str:
    """
    Accepts a domain-like string and returns scheme+netloc base URL.
    Rejects paths, queries, fragments, ports embedded in input, etc.
    """
    if domain is None:
        raise ValueError("INVALID_DOMAIN")

    d = domain.strip()
    if not d:
        raise ValueError("INVALID_DOMAIN")

    # Disallow obvious URL/path input
    if "/" in d or "?" in d or "#" in d or "@" in d:
        # We only accept a bare domain (optionally with scheme)
        # but ANY path/query/fragment is rejected.
        if d.startswith(("http://", "https://")):
            parsed = urlparse(d)
            if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                raise ValueError("INVALID_DOMAIN")
        else:
            raise ValueError("INVALID_DOMAIN")

    # Add scheme if missing
    if not d.startswith(("http://", "https://")):
        d = "https://" + d

    parsed = urlparse(d)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("INVALID_DOMAIN")

    if not parsed.netloc:
        raise ValueError("INVALID_DOMAIN")

    # Reject explicit port in netloc (keep v1 simple and safe)
    if ":" in parsed.netloc:
        raise ValueError("INVALID_DOMAIN")

    host = parsed.netloc.lower()

    # Block localhost / obvious internal suffixes
    if host == "localhost" or host.endswith(".local") or host.endswith(".internal"):
        raise ValueError("PRIVATE_IP_BLOCKED")

    return f"{parsed.scheme}://{host}"


def _resolve_ipv4(host: str) -> str:
    """
    Resolve host to IPv4. Keep v1 simple; Render/Linux will support IPv6,
    but SSRF guard still works on IPv4 resolution.
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError("DOMAIN_UNRESOLVABLE")


def block_private_or_reserved_ip(host: str) -> str:
    """
    Resolve host and block private/loopback/link-local/reserved ranges.
    Returns resolved IP string if acceptable.
    """
    ip_str = _resolve_ipv4(host)
    ip = ipaddress.ip_address(ip_str)

    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        raise ValueError("PRIVATE_IP_BLOCKED")

    return ip_str


# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------

def normalize_url(u: str) -> str:
    u, _ = urldefrag(u)
    parsed = urlparse(u)

    scheme = (parsed.scheme or "https").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    if path == "/":
        path = ""

    return f"{scheme}://{netloc}{path}"


def extract_jsonld(soup: BeautifulSoup) -> List[Any]:
    blocks: List[Any] = []
    for tag in soup.find_all("script", type="application/ld+json"):
        try:
            if tag.string:
                blocks.append(json.loads(tag.string))
        except Exception:
            continue
    return blocks


def extract_entities(block: Any) -> List[Dict[str, Any]]:
    if isinstance(block, dict) and "@graph" in block and isinstance(block["@graph"], list):
        return [x for x in block["@graph"] if isinstance(x, dict)]
    if isinstance(block, dict):
        return [block]
    return []


# ------------------------------------------------------------
# CRAWL (HARDENED)
# ------------------------------------------------------------

def load_live_site(base_url: str) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[str]]]:
    """
    Crawls within the same host only.
    Returns:
      pages: {url: {"html": "<str>", "depth": int}}
      crawl_graph: {url: [internal_url, ...]}
    """
    pages: Dict[str, Dict[str, Any]] = {}
    crawl_graph: Dict[str, List[str]] = {}

    visited: set[str] = set()
    queue: List[Tuple[str, int]] = [(base_url, 0)]

    domain_host = urlparse(base_url).netloc.lower()

    session = requests.Session()
    session.headers.update({
        # Browser-like UA. (This is the single biggest unblocker.)
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        # These help a lot of CDNs decide you're "normal".
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
    })

    while queue and len(visited) < MAX_PAGES:
        url, depth = queue.pop(0)

        if depth > MAX_DEPTH:
            continue

        normalized = normalize_url(url)

        if normalized in visited:
            continue

        # Scope lock: do not crawl outside host
        if urlparse(normalized).netloc.lower() != domain_host:
            continue

        visited.add(normalized)

        try:
            r = session.get(
                normalized,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            r.raise_for_status()

            # Redirect safety: reject cross-host redirects
            final_url = normalize_url(r.url)
            if urlparse(final_url).netloc.lower() != domain_host:
                continue

            content = r.content[:MAX_BYTES] if len(r.content) > MAX_BYTES else r.content
            html = content.decode(errors="ignore")

        except Exception:
            continue

        pages[normalized] = {"html": html, "depth": depth}

        soup = BeautifulSoup(html, "lxml")
        internal_links: List[str] = []

        for a in soup.find_all("a", href=True):
            full = urljoin(normalized, a["href"])
            full, _ = urldefrag(full)

            parsed = urlparse(full)

            if parsed.scheme not in ("http", "https"):
                continue

            if parsed.netloc.lower() != domain_host:
                continue

            next_url = normalize_url(full)
            internal_links.append(next_url)

            if next_url not in visited and (depth + 1) <= MAX_DEPTH:
                queue.append((next_url, depth + 1))

        crawl_graph[normalized] = internal_links

    return pages, crawl_graph


# ------------------------------------------------------------
# DIMENSION 1 — ENTITY EXPLICITNESS
# ------------------------------------------------------------

def evaluate_entity_explicitness(site_pages: Dict[str, Dict[str, Any]]) -> Tuple[float, Dict[str, Any], Dict[str, Any]]:
    primary_entities: List[Dict[str, Any]] = []
    entity_ids: List[str] = []
    entity_names: set[str] = set()

    for _, data in site_pages.items():
        soup = BeautifulSoup(data["html"], "lxml")

        for block in extract_jsonld(soup):
            for e in extract_entities(block):
                if e.get("@type") in ["Person", "Organization"]:
                    primary_entities.append(e)
                    if e.get("@id"):
                        entity_ids.append(str(e["@id"]))
                    if e.get("name"):
                        entity_names.add(str(e["name"]))

    checks = {
        "EE1_PRIMARY_ENTITY_PRESENT": len(primary_entities) >= 1,
        "EE2_STABLE_ENTITY_ID": (len(set(entity_ids)) == 1) if entity_ids else False,
        "EE3_CONSISTENT_ENTITY_NAME": (len(entity_names) == 1) if entity_names else False,
    }

    score = round(sum(bool(v) for v in checks.values()) / len(checks) * 100, 2)
    return score, checks, {}


# ------------------------------------------------------------
# DIMENSION 2 — IDENTIFIER STABILITY
# ------------------------------------------------------------

def evaluate_identifier_stability(site_pages: Dict[str, Dict[str, Any]], base_url: str) -> Tuple[float, Dict[str, Any], Dict[str, Any]]:
    issues = {
        "canonical_missing": [],
        "canonical_wrong": [],
        "http_internal_links": [],
    }

    domain_host = urlparse(base_url).netloc.lower()

    for url, data in site_pages.items():
        soup = BeautifulSoup(data["html"], "lxml")

        canon = soup.find("link", rel="canonical")
        if not canon or not canon.get("href"):
            issues["canonical_missing"].append(url)
        else:
            expected = normalize_url(url)
            actual = normalize_url(urljoin(url, str(canon["href"])))
            if actual != expected:
                issues["canonical_wrong"].append((url, actual, expected))

        for a in soup.find_all("a", href=True):
            full = urljoin(url, a["href"])
            parsed = urlparse(full)
            if parsed.netloc.lower() == domain_host and parsed.scheme == "http":
                issues["http_internal_links"].append((url, a["href"]))

    checks = {
        "IS1_CANONICAL_PRESENT": len(issues["canonical_missing"]) == 0,
        "IS2_CANONICAL_CORRECT": len(issues["canonical_wrong"]) == 0,
        "IS3_NO_HTTP_INTERNAL_LINKS": len(issues["http_internal_links"]) == 0,
    }

    score = round(sum(bool(v) for v in checks.values()) / len(checks) * 100, 2)
    return score, checks, issues


# ------------------------------------------------------------
# DIMENSION 3 — HIERARCHICAL CLARITY
# ------------------------------------------------------------

def evaluate_hierarchical_clarity(site_pages: Dict[str, Dict[str, Any]]) -> Tuple[float, Dict[str, Any], Dict[str, Any]]:
    h1_issues: List[str] = []
    heading_skips: List[str] = []

    for url, data in site_pages.items():
        soup = BeautifulSoup(data["html"], "lxml")

        if len(soup.find_all("h1")) != 1:
            h1_issues.append(url)

        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        prev = None
        for h in headings:
            level = int(h.name[1])
            if prev is not None and (level - prev) > 1:
                heading_skips.append(url)
                break
            prev = level

    checks = {
        "HC1_SINGLE_H1": len(h1_issues) == 0,
        "HC2_NO_HEADING_SKIPS": len(heading_skips) == 0,
    }

    score = round(sum(bool(v) for v in checks.values()) / len(checks) * 100, 2)
    return score, checks, {"H1_ISSUES": h1_issues, "HEADING_SKIPS": heading_skips}


# ------------------------------------------------------------
# DIMENSION 4 — SURFACE COHERENCE
# ------------------------------------------------------------

def evaluate_surface_coherence(site_pages: Dict[str, Dict[str, Any]]) -> Tuple[float, Dict[str, Any], Dict[str, Any]]:
    duplicate_titles: List[str] = []
    missing_titles: List[str] = []
    title_map: Dict[str, str] = {}

    for url, data in site_pages.items():
        soup = BeautifulSoup(data["html"], "lxml")
        title = soup.title.string.strip() if soup.title and soup.title.string else None

        if not title:
            missing_titles.append(url)
        else:
            if title in title_map:
                duplicate_titles.append(url)
            else:
                title_map[title] = url

    checks = {
        "SC1_TITLE_PRESENT": len(missing_titles) == 0,
        "SC2_NO_DUPLICATE_TITLES": len(duplicate_titles) == 0,
    }

    score = round(sum(bool(v) for v in checks.values()) / len(checks) * 100, 2)
    return score, checks, {"MISSING_TITLES": missing_titles, "DUPLICATE_TITLES": duplicate_titles}


# ------------------------------------------------------------
# DIMENSION 5 — STRUCTURAL GRAPH INTEGRITY
# ------------------------------------------------------------

def evaluate_structural_graph(site_pages: Dict[str, Dict[str, Any]], crawl_graph: Dict[str, List[str]], base_url: str) -> Tuple[float, Dict[str, Any], Dict[str, Any]]:
    orphan_pages: List[str] = []
    deep_pages: List[Tuple[str, int]] = []
    zero_outbound: List[str] = []

    inbound_map = {url: 0 for url in site_pages.keys()}

    for _, targets in crawl_graph.items():
        for target in targets:
            if target in inbound_map:
                inbound_map[target] += 1

    homepage = normalize_url(base_url)

    for url, data in site_pages.items():
        # Orphan detection (exclude homepage)
        if url != homepage and inbound_map.get(url, 0) == 0:
            orphan_pages.append(url)

        depth = int(data.get("depth", 0))
        if depth > MAX_DEPTH:
            deep_pages.append((url, depth))

        if len(crawl_graph.get(url, [])) == 0:
            zero_outbound.append(url)

    checks = {
        "SG1_NO_ORPHAN_PAGES": len(orphan_pages) == 0,
        "SG2_DEPTH_WITHIN_LIMIT": len(deep_pages) == 0,
        "SG3_NO_ISOLATED_PAGES": len(zero_outbound) == 0,
    }

    score = round(sum(bool(v) for v in checks.values()) / len(checks) * 100, 2)
    issues = {
        "ORPHAN_PAGES": orphan_pages,
        "DEPTH_EXCEEDED": deep_pages,
        "ZERO_OUTBOUND_LINKS": zero_outbound,
    }
    return score, checks, issues


# ------------------------------------------------------------
# DIMENSION 6 — ENTITY RESOLUTION INTENSITY
# ------------------------------------------------------------

def evaluate_resolution_intensity(site_pages: Dict[str, Dict[str, Any]]) -> Tuple[float, Dict[str, Any], Dict[str, Any]]:
    entity_name: Optional[str] = None
    reinforcement_pages: List[str] = []
    weak_pages: List[str] = []

    # Detect primary entity name from JSON-LD
    for _, data in site_pages.items():
        soup = BeautifulSoup(data["html"], "lxml")
        for block in extract_jsonld(soup):
            for e in extract_entities(block):
                if e.get("@type") in ["Person", "Organization"] and e.get("name"):
                    entity_name = str(e["name"])
                    break
            if entity_name:
                break
        if entity_name:
            break

    if not entity_name:
        return 0.0, {"RI1_ENTITY_DISCOVERED": False}, {}

    needle = entity_name.lower()

    for url, data in site_pages.items():
        soup = BeautifulSoup(data["html"], "lxml")
        text = soup.get_text(separator=" ").lower()
        first_chunk = " ".join(text.split()[:250])

        if needle in first_chunk:
            reinforcement_pages.append(url)
        else:
            weak_pages.append(url)

    coverage_ratio = (len(reinforcement_pages) / len(site_pages)) if site_pages else 0.0
    coverage_ratio_percent = round(coverage_ratio * 100, 2)

    # Continuous scoring (preserved logic)
    entity_score = 50.0
    reinforcement_score = coverage_ratio_percent * 0.5
    score = round(entity_score + reinforcement_score, 2)

    checks = {
        "RI1_ENTITY_DISCOVERED": True,
        "RI2_REINFORCEMENT_COVERAGE_PERCENT": coverage_ratio_percent,
    }

    issues = {"WEAK_ENTITY_REINFORCEMENT": weak_pages}

    return score, checks, issues


# ------------------------------------------------------------
# PUBLIC ENTRY POINT
# ------------------------------------------------------------

def run_scan(domain: str) -> Dict[str, Any]:
    """
    Public API-safe call:
      - validates domain
      - blocks private/reserved IPs
      - crawls within same host (capped)
      - returns structured diagnostic JSON
    """
    scan_timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    # Validate + SSRF guard
    try:
        base_url = canonicalise_domain(domain)
        host = urlparse(base_url).netloc
        resolved_ip = block_private_or_reserved_ip(host)
    except ValueError as e:
        return {
            "status": "error",
            "error_code": str(e),
            "engine_version": ENGINE_VERSION,
            "scan_timestamp": scan_timestamp,
        }

    # Crawl
    site_pages, crawl_graph = load_live_site(base_url)

    if not site_pages:
        return {
            "status": "error",
            "error_code": "CRAWL_BLOCKED_OR_EMPTY",
            "engine_version": ENGINE_VERSION,
            "scan_timestamp": scan_timestamp,
        }

    # Evaluate
    results: Dict[str, Dict[str, Any]] = {}

    evaluators = [
        ("ENTITY EXPLICITNESS", lambda: evaluate_entity_explicitness(site_pages)),
        ("IDENTIFIER STABILITY", lambda: evaluate_identifier_stability(site_pages, base_url)),
        ("STRUCTURAL GRAPH INTEGRITY", lambda: evaluate_structural_graph(site_pages, crawl_graph, base_url)),
        ("HIERARCHICAL CLARITY", lambda: evaluate_hierarchical_clarity(site_pages)),
        ("SURFACE COHERENCE", lambda: evaluate_surface_coherence(site_pages)),
        ("ENTITY RESOLUTION INTENSITY", lambda: evaluate_resolution_intensity(site_pages)),
    ]

    for name, fn in evaluators:
        score, checks, issues = fn()
        results[name] = {"score": score, "checks": checks, "issues": issues}

    # Composite
    composite = 0.0
    for dim, data in results.items():
        composite += float(data["score"]) * WEIGHTS[dim]
    composite = round(composite, 1)

    band = "Strong" if composite >= 75 else "Moderate" if composite >= 50 else "Weak"

    return {
        "status": "complete",
        "domain": base_url,
        "resolved_ip": resolved_ip,
        "engine_version": ENGINE_VERSION,
        "scan_timestamp": scan_timestamp,
        "limits": {
            "max_pages": MAX_PAGES,
            "max_depth": MAX_DEPTH,
            "request_timeout_seconds": REQUEST_TIMEOUT,
            "max_bytes_per_page": MAX_BYTES,
        },
        "pages_loaded": len(site_pages),
        "composite_score": composite,
        "band": band,
        "dimensions": results,
    }