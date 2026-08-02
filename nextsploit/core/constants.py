"""
nextsploit/core/constants.py — Centralized framework constants for NextSploit.
"""

# Default framework settings
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 10
DEFAULT_USER_AGENT = "NextSploit Auditing Framework/4.0.0"

# Event Bus Event Names
class Events:
    TARGET_VALIDATED = "target_validated"
    RECON_COMPLETE = "recon_complete"
    FINGERPRINT_COMPLETE = "fingerprint_complete"
    CAPABILITY_DISCOVERED = "capability_discovered"
    MODULE_RESOLVED = "module_resolved"
    MODULE_STARTED = "module_started"
    MODULE_FINISHED = "module_finished"
    FINDING_FOUND = "finding_found"
    REQUEST_SENT = "request_sent"
    REQUEST_RECEIVED = "request_received"
    REPORT_GENERATED = "report_generated"
    METRIC_UPDATED = "metric_updated"


# Vulnerability Severities
class Severities:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"
