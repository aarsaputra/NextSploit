"""
nextsploit/phases/recon.py — Phase 1: Recon & WAF Detection.
"""

from urllib.parse import urljoin
from nextsploit.core.context import ScanContext
from nextsploit.core.logger import log_info, log_success, log_warning


class ReconPhase:
    """
    Phase 1: Recon & WAF Detection.
    Parses headers, cookies, robots.txt, and detects WAF/CDN providers.
    """
    name = "Recon & WAF Detection"

    def run(self, context: ScanContext) -> None:
        log_info("Starting passive reconnaissance...")
        
        # 1. Fetch home page and inspect headers & cookies
        try:
            resp = context.session.get(
                context.target,
                timeout=context.config.timeout,
                verify=context.config.verify_ssl
            )
        except Exception as e:
            log_warning(f"Failed to fetch home page for header recon: {e}")
            return

        headers = resp.headers
        cookies = resp.cookies

        # 2. Populate headers and cookies in target profile (lowercase keys for normalization)
        context.profile.headers = {k.lower(): v for k, v in headers.items()}
        context.profile.cookies = [
            {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
            for c in cookies
        ]

        # 3. Check for Cloudflare / WAF Headers
        waf_detected = []
        profile_headers = context.profile.headers
        if "cf-ray" in profile_headers or "server" in profile_headers and "cloudflare" in profile_headers["server"].lower():
            waf_detected.append("Cloudflare")
            context.profile.cdn = "Cloudflare"
        if "x-sucuri-id" in profile_headers:
            waf_detected.append("Sucuri")
        if "x-amz-cf-id" in profile_headers:
            waf_detected.append("AWS WAF / Cloudfront")
            context.profile.cdn = "AWS CloudFront"
        if "x-cdn" in profile_headers:
            waf_detected.append(profile_headers["x-cdn"])

        if waf_detected:
            context.profile.waf = waf_detected[0]
            log_success(f"WAF/CDN detected: [bold yellow]{', '.join(waf_detected)}[/bold yellow]")
        else:
            log_info("No obvious WAF/CDN signature detected in HTTP headers.")

        # 4. Scan robots.txt and sitemap.xml
        self._check_robots(context)
        self._check_sitemap(context)

    def _check_robots(self, context: ScanContext) -> None:
        robots_url = urljoin(context.target, "/robots.txt")
        log_info("Probing robots.txt...")
        try:
            resp = context.session.get(
                robots_url,
                timeout=context.config.timeout,
                verify=context.config.verify_ssl
            )
            if resp.status_code == 200:
                log_success("robots.txt is publicly accessible.")
                context.profile.robots = robots_url
                context.profile.evidence["robots_txt_content"] = resp.text[:2000]
            else:
                log_info(f"robots.txt returned status: {resp.status_code}")
        except Exception as e:
            log_warning(f"Error probing robots.txt: {e}")

    def _check_sitemap(self, context: ScanContext) -> None:
        sitemap_url = urljoin(context.target, "/sitemap.xml")
        log_info("Probing sitemap.xml...")
        try:
            resp = context.session.get(
                sitemap_url,
                timeout=context.config.timeout,
                verify=context.config.verify_ssl
            )
            if resp.status_code == 200:
                log_success("sitemap.xml is publicly accessible.")
                context.profile.sitemap = sitemap_url
                context.profile.evidence["sitemap_xml_exists"] = True
            else:
                log_info(f"sitemap.xml returned status: {resp.status_code}")
        except Exception as e:
            log_warning(f"Error probing sitemap.xml: {e}")

