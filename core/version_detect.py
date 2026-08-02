#!/usr/bin/env python3
"""
NextSploit — Multi-Signal Next.js Version Detection Engine
Calculates Next.js framework version using multiple signal sources,
handling React/Next.js correlation, minified packages, and error leaks.
"""

import re
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Set
import requests

from core.output import log_info, log_success, log_warning, log_debug, log_trace

# React to Next.js version correlation mapping
# Format: ((React major, React minor), Next.js low range, Next.js high range)
# Next.js ranges format: (major, minor, patch)
REACT_RANGES = [
    (("19", "0"), (15, 0, 0), (15, 99, 99)),
    (("19", "1"), (15, 5, 0), (16, 99, 99)),
    (("19", "2"), (16, 0, 0), (16, 99, 99)),
    (("19", "3"), (16, 2, 0), (16, 99, 99)),
    (("18", "3"), (14, 1, 0), (14, 99, 99)),
    (("18", "2"), (12, 2, 0), (14, 0, 99)),
    (("17", "0"), (10, 0, 0), (12, 1, 99)),
]


def _parse(v: str) -> Optional[Tuple[int, int, int, str, int]]:
    """Parse semver string into a comparable tuple: (major, minor, patch, prerelease, pre_num)."""
    # Clean string: strip whitespace, remove leading 'v'
    v_clean = v.strip().lstrip("v")
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.-]+))?$", v_clean)
    if not m:
        return None
    
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3))
    
    prerelease = ""
    pre_num = 0
    
    pre_raw = m.group(4)
    if pre_raw:
        prerelease = pre_raw
        # Try to extract trailing number from prerelease (e.g. canary.3 -> 3)
        num_m = re.search(r'\.(\d+)$', pre_raw)
        if num_m:
            pre_num = int(num_m.group(1))
            
    return (major, minor, patch, prerelease, pre_num)


def _to_str(t: Tuple[int, int, int, str, int]) -> str:
    """Convert version tuple back to semver string."""
    base = f"{t[0]}.{t[1]}.{t[2]}"
    if t[3]:
        base += f"-{t[3]}"
    return base


def _to_comparable(t: Tuple[int, int, int, str, int]) -> Tuple[int, int, int, int, str, int]:
    """Helper to make version tuples comparable (prereleases are older than stable versions)."""
    # Stable version is newer than any prerelease of the same major.minor.patch
    is_stable = 1 if t[3] == "" else 0
    return (t[0], t[1], t[2], is_stable, t[3], t[4])


@dataclass
class Signal:
    name: str
    confidence: float
    exact: Optional[Tuple[int, int, int, str, int]] = None
    low: Optional[Tuple[int, int, int]] = None
    high: Optional[Tuple[int, int, int]] = None
    evidence: str = ""


class VersionDetector:
    """
    Multi-Signal Next.js Version Detection Engine.
    """

    def __init__(self, session: requests.Session, target: str, config) -> None:
        self.session = session
        self.target = target.rstrip("/")
        self.config = config
        self.signals: List[Signal] = []
        self.discovered_chunks: Set[str] = set()
        self.crawled_urls: Set[str] = {self.target}
        self.router_type = None
        self.mined_js_texts: List[str] = []

        # Regex patterns for mining bundle sources
        self.NEXT_PKG_INLINE_RE = re.compile(
            r'(?:"name"|\'name\'|name)\s*:\s*["\']next["\']\s*,\s*(?:"version"|\'version\'|version)\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+[^"\']*)["\']'
        )
        self.NEXT_PKG_NEAR_RE = re.compile(
            r'node_modules[\\/]next[\\/]package\.json.{0,700}?(?:"version"|\'version\'|version)\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+[^"\']*)["\']',
            re.S
        )
        self.REACT_PKG_INLINE_RE = re.compile(
            r'(?:"name"|\'name\'|name)\s*:\s*["\']react["\']\s*,\s*(?:"version"|\'version\'|version)\s*:\s*["\']([0-9]+\.[0-9]+\.[0-9]+[^"\']*)["\']'
        )
        self.WINDOW_NEXT_VAL_RE = re.compile(
            r'window\.next\s*=\s*\{[^{}]*version\s*:\s*["\'](\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)["\']'
        )
        self.WINDOW_NEXT_VER_RE = re.compile(
            r'window\.next\.version\s*=\s*["\'](\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)["\']'
        )
        self.NEXT_VERSION_ERR_RE = re.compile(
            r'"nextVersion"\s*:\s*"([^"]+)"'
        )

    def detect(self) -> dict:
        """
        Execute the full multi-signal version detection routine.
        """
        log_info("Starting Multi-Signal version detection...")
        
        # 1. Harvest target homepage and extract initial chunks + internal sub-page links
        self._crawl_page(self.target)

        # 2. Crawl up to 3 sub-pages to harvest more chunks (handles dynamic chunk splitting)
        subpages = self._find_internal_links()
        for page in list(subpages)[:3]:
            self._crawl_page(page)

        # 3. Mine the harvested bundles for exact metadata
        self._mine_bundles()

        # 4. Try error leak probing (only if version not confidently resolved yet)
        if not any(s.exact and s.confidence >= 0.95 for s in self.signals):
            self._error_leak_probe()

        # 5. Run active heuristic probes (RSC, Server Actions, Middleware chunks)
        self._active_probes()

        # 6. Resolve conflict and calculate final version
        return self._resolve_signals()

    def _crawl_page(self, url: str) -> None:
        """Fetch a page, extract its chunk URLs, and check headers."""
        if url in self.crawled_urls and url != self.target:
            return
        self.crawled_urls.add(url)
        
        log_debug(f"Crawling page: {url}")
        try:
            self.config.throttle()
            r = self.session.get(url, timeout=self.config.timeout)
            self.config.record_request(r.status_code, response=r)
            if r.status_code != 200:
                return

            # Analyze headers
            powered_by = r.headers.get("X-Powered-By", "")
            if "next" in powered_by.lower():
                ver_match = re.search(r'next\.js\s*v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)', powered_by, re.IGNORECASE)
                if ver_match:
                    ver = _parse(ver_match.group(1))
                    if ver:
                        self.signals.append(Signal("header_powered_by", 0.9, exact=ver, evidence=f"X-Powered-By: {powered_by}"))
            
            if r.headers.get("x-nextjs-cache") or r.headers.get("x-vercel-cache"):
                self.signals.append(Signal("header_cache", 0.6, low=(12, 0, 0), evidence="Next.js caching headers present"))

            # Normalize and harvest chunks
            body = r.text.replace('\\/', '/')
            js_paths = re.findall(r'(/_next/static/[^\s"\'\\{}()<>]+.js)', body)
            for js in js_paths:
                self.discovered_chunks.add(js)
                
            # Router type detection
            if "/_next/static/chunks/app/" in body or "/_next/static/css/app/" in body:
                self.router_type = "app"
            elif "/_next/static/chunks/pages/" in body or "/_next/static/css/pages/" in body:
                if self.router_type != "app":
                    self.router_type = "pages"

            # Parse Build ID from chunks path
            bid_match = re.search(r'/_next/static/([^/]+)/_buildManifest\.js', body)
            if bid_match:
                build_id = bid_match.group(1)
                log_debug(f"Discovered Build ID: {build_id}")
                self.config.discovered_build_id = build_id

        except Exception as e:
            log_debug(f"Error crawling page {url}: {e}")

    def _find_internal_links(self) -> Set[str]:
        """Extract unique internal links from crawled URLs for chunk harvesting."""
        links = set()
        for url in list(self.crawled_urls):
            try:
                # Retrieve from history/cache if already retrieved
                # For simplicity, we just parse page text of target
                r = self.session.get(url, timeout=self.config.timeout)
                body = r.text
                # Find links starting with / or target host
                found = re.findall(r'href=["\'](/[^"\']+)["\']', body)
                for f in found:
                    if f.startswith("/_next") or f.startswith("//") or "." in f.split("/")[-1]:
                        continue
                    links.add(urllib.parse.urljoin(self.target, f))
            except Exception:
                pass
        return links

    def _mine_bundles(self) -> None:
        """Download and mine prioritized JavaScript chunks for version strings."""
        if not self.discovered_chunks:
            log_debug("No JS chunks harvested to mine.")
            return

        # Prioritize chunks that typically contain react-dom / next internals
        def chunk_priority(path: str) -> int:
            path_lower = path.lower()
            if "framework" in path_lower:
                return 0
            if "main" in path_lower:
                return 1
            if "webpack" in path_lower:
                return 2
            if "turbopack" in path_lower:
                return 3
            if "core" in path_lower:
                return 4
            if "layout" in path_lower:
                return 5
            return 10

        sorted_chunks = sorted(self.discovered_chunks, key=chunk_priority)
        
        # Scan up to 15 chunks (enough to find framework / webpack chunks)
        scanned_count = 0
        for chunk_path in sorted_chunks[:15]:
            chunk_url = urllib.parse.urljoin(self.target, chunk_path)
            log_debug(f"Mining chunk: {chunk_path}")
            try:
                self.config.throttle()
                r = self.session.get(chunk_url, timeout=self.config.timeout)
                self.config.record_request(r.status_code, response=r)
                if r.status_code != 200:
                    continue
                
                scanned_count += 1
                body = r.text
                self.mined_js_texts.append(body)

                # 1. Look for window.next version assignment (Next.js entrypoint)
                wm = self.WINDOW_NEXT_VAL_RE.search(body)
                if not wm:
                    wm = self.WINDOW_NEXT_VER_RE.search(body)
                if wm:
                    ver = _parse(wm.group(1))
                    if ver:
                        self.signals.append(Signal(
                            "window_next_version", 1.0, exact=ver,
                            evidence=f"{chunk_path} -> window.next={wm.group(0)}"
                        ))
                        log_success(f"Detected exact version from window.next: [bold green]{wm.group(1)}[/bold green]")
                        # Confident exact match: stop scanning to save requests
                        return

                # 2. Look for package.json next metadata
                nm = self.NEXT_PKG_INLINE_RE.search(body)
                if not nm:
                    nm = self.NEXT_PKG_NEAR_RE.search(body)
                if nm:
                    ver = _parse(nm.group(1))
                    if ver:
                        self.signals.append(Signal(
                            "bundle_package_json", 0.95, exact=ver,
                            evidence=f"{chunk_path} -> next package version: {nm.group(1)}"
                        ))
                        log_success(f"Detected version from next package metadata: [bold green]{nm.group(1)}[/bold green]")
                        return

                # 3. Look for React package metadata to infer Next.js range constraint
                rm = self.REACT_PKG_INLINE_RE.search(body)
                if rm:
                    react_ver = rm.group(1)
                    log_debug(f"React version found in bundle: {react_ver}")
                    for rv, lo, hi in REACT_RANGES:
                        if react_ver.startswith(".".join(rv)):
                            self.signals.append(Signal(
                                "react_version_correlation", 0.7,
                                low=lo, high=hi,
                                evidence=f"{chunk_path} -> react@{react_ver} correlates to Next.js ranges"
                            ))
                            break

            except Exception as e:
                log_trace(f"Error mining chunk {chunk_path}: {e}")

        log_debug(f"Finished mining {scanned_count} JS chunks.")

    def _error_leak_probe(self) -> None:
        """Probe Next.js error data pages to leak version info."""
        # Using build_id if discovered, otherwise default
        build_id = getattr(self.config, "discovered_build_id", None)
        if not build_id:
            build_id = "nonexistent"

        leak_paths = [
            f"/_next/data/{build_id}/404.json",
            f"/_next/data/{build_id}/index.json",
        ]

        for path in leak_paths:
            probe_url = self.target + path
            log_debug(f"Probing error leak: {path}")
            try:
                self.config.throttle()
                r = self.session.get(probe_url, timeout=self.config.timeout)
                self.config.record_request(r.status_code, response=r)
                
                # Check headers
                powered_by = r.headers.get("X-Powered-By", "")
                if "next" in powered_by.lower():
                    ver_match = re.search(r'next\.js\s*v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)', powered_by, re.IGNORECASE)
                    if ver_match:
                        ver = _parse(ver_match.group(1))
                        if ver:
                            self.signals.append(Signal("error_leak_header", 0.95, exact=ver, evidence=f"Error page X-Powered-By: {powered_by}"))
                            return

                if r.status_code == 404 and r.headers.get("content-type", "").startswith("application/json"):
                    # Check body for nextVersion
                    m = self.NEXT_VERSION_ERR_RE.search(r.text)
                    if m:
                        ver = _parse(m.group(1))
                        if ver:
                            self.signals.append(Signal(
                                "error_leak_payload", 0.95, exact=ver,
                                evidence=f"{path} response payload leaked nextVersion={m.group(1)}"
                            ))
                            log_success(f"Leaked Next.js version from error payload: [bold green]{m.group(1)}[/bold green]")
                            return
            except Exception as e:
                log_trace(f"Error probing leak path {path}: {e}")

    def _active_probes(self) -> None:
        """Active heuristic probes (RSC, Server Action verification, middleware detection)."""
        # RSC Header check
        try:
            self.config.throttle()
            r = self.session.get(self.target + "/", headers={"RSC": "1"}, timeout=self.config.timeout)
            self.config.record_request(r.status_code, response=r)
            if r.status_code == 200 and ("x-router-state-tree" in r.headers or "x-router-pref" in r.headers):
                self.router_type = "app"
                self.signals.append(Signal("rsc_header_probe", 0.8, low=(13, 4, 0), evidence="RSC response headers confirmed App Router"))
        except Exception:
            pass

        # Middleware bundle probe
        try:
            self.config.throttle()
            r = self.session.get(self.target + "/_next/static/chunks/middleware.js", timeout=self.config.timeout)
            self.config.record_request(r.status_code, response=r)
            if r.status_code == 200:
                self.signals.append(Signal("middleware_bundle_probe", 0.8, low=(12, 0, 0), evidence="Middleware bundle is present"))
        except Exception:
            pass

    def _resolve_signals(self) -> dict:
        """Resolve conflict signals to determine final version and confidence."""
        # 1. Check exact signals first
        exact_signals = [s for s in self.signals if s.exact]
        if exact_signals:
            # Sort by confidence first, then priority
            best = max(exact_signals, key=lambda s: s.confidence)
            ver_str = _to_str(best.exact)
            log_success(f"Resolved exact version: [bold cyan]{ver_str}[/bold cyan] (Confidence: {best.confidence:.2f} via {best.name})")
            return {
                "version": ver_str,
                "confidence": best.confidence,
                "source": best.name,
                "evidence": best.evidence,
                "router": self.router_type
            }

        # 2. Intersect ranges
        low_bounds = [s.low for s in self.signals if s.low]
        high_bounds = [s.high for s in self.signals if s.high]

        final_low = max(low_bounds) if low_bounds else None
        final_high = min(high_bounds) if high_bounds else None

        if final_low or final_high:
            low_str = ".".join(str(x) for x in final_low) if final_low else "0.0.0"
            high_str = ".".join(str(x) for x in final_high) if final_high else "99.99.99"
            evidence_list = [s.evidence for s in self.signals if s.low or s.high]
            evidence_str = "; ".join(evidence_list)
            
            # Since we can't pinpoint a single exact version, we report the lowest bound (or high bound if low absent)
            # but with lower confidence, indicating version estimation.
            repr_version = low_str if final_low else high_str
            log_warning(f"Pinpointed version range: Next.js >= {low_str} and <= {high_str} (estimating as {repr_version})")
            return {
                "version": repr_version,
                "confidence": 0.5,
                "source": "range_intersection",
                "evidence": f"Range: [{low_str}, {high_str}] | Evidence: {evidence_str}",
                "router": self.router_type
            }

        log_warning("No Next.js version signals discovered.")
        return {
            "version": None,
            "confidence": 0.0,
            "source": "none",
            "evidence": "No signals",
            "router": self.router_type
        }
