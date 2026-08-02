"""
nextsploit/phases/fingerprint.py — Phase 2: Fingerprinting.
"""

from nextsploit.core.context import ScanContext
from nextsploit.core.logger import log_info, log_success, log_warning, log_debug
from core.version_detect import VersionDetector


class FingerprintPhase:
    """
    Phase 2: Fingerprinting.
    Detects framework version, router type (App Router/Pages Router), Build ID,
    and lists JavaScript/CSS chunks.
    """
    name = "Fingerprinting"

    def run(self, context: ScanContext) -> None:
        log_info("Executing framework version and component fingerprinting...")
        
        # Instantiate the version detector
        detector = VersionDetector(context.session, context.target, context.config)
        res = detector.detect()

        # Populate TargetProfile with the detected information
        profile = context.profile
        profile.framework_version = res.get("version")
        profile.router = res.get("router")
        profile.build_id = res.get("build_id")
        
        # Hosting provider identification from headers
        headers_lower = {k.lower(): v.lower() for k, v in profile.headers.items()}
        if "x-vercel-id" in headers_lower or "server" in headers_lower and "vercel" in headers_lower["server"]:
            profile.hosting = "Vercel"
        elif "x-nf-request-id" in headers_lower:
            profile.hosting = "Netlify"
        else:
            profile.hosting = "Self-Hosted"
            
        if hasattr(detector, "discovered_chunks") and detector.discovered_chunks:
            profile.js_chunks = list(detector.discovered_chunks)

        log_debug(f"Fingerprint raw results: {res}")

        if profile.framework_version:
            log_success(f"Next.js version detected: [bold green]{profile.framework_version}[/bold green] (Confidence: {res.get('confidence', 0.0):.2f})")
        else:
            log_warning("Next.js version could not be resolved with high confidence.")

        if profile.router:
            log_success(f"Next.js router architecture: [bold cyan]{profile.router.capitalize()} Router[/bold cyan]")
            if profile.router == "app":
                profile.rsc = True

        if profile.build_id:
            log_success(f"Discovered Build ID: [bold cyan]{profile.build_id}[/bold cyan]")

        # Check for Server Actions
        is_action_detected = False
        for s in detector.signals:
            if s.name == "server_action_id_leak" or "action_id_probe" in res.get("evidence", {}):
                is_action_detected = True
                break
        profile.server_actions = is_action_detected

        # Check for Turbopack
        is_turbo = False
        for s in detector.signals:
            if "turbopack" in s.name:
                is_turbo = True
                break
        profile.turbopack = is_turbo

        # Register capabilities dynamically in profile
        profile.capabilities["server_actions"] = {
            "name": "Server Actions",
            "detected": profile.server_actions,
            "confidence": 0.9 if profile.server_actions else 0.0,
            "source": "bundle_probe",
            "evidence": res.get("evidence", {})
        }
        profile.capabilities["rsc"] = {
            "name": "React Server Components (RSC)",
            "detected": profile.rsc,
            "confidence": 1.0 if profile.rsc else 0.0,
            "source": "router_detection",
            "evidence": {}
        }

