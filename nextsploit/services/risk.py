"""
nextsploit/services/risk.py — Risk Engine computing dynamic risk scores based on multidimensional telemetry.
"""

from typing import Any, Dict
from nextsploit.interfaces.risk import IRiskEngine
from nextsploit.interfaces.reporter import IFinding


class RiskEngine(IRiskEngine):
    """
    Evaluates finding risk score (0-100) and priority category based on:
    - Base Severity
    - Detection Confidence
    - WAF presence & Exploitability
    - Evidence Quality
    - False Positive Probability
    """

    def calculate_cvss(self, finding: IFinding) -> float:
        """
        Calculate a CVSS-like score (0-10) based on finding parameters.
        Maps dynamic risk score to 0-10 scale.
        """
        score_100 = self.calculate_risk_score(finding)
        return round(score_100 / 10.0, 1)

    def evaluate_confidence(self, finding: IFinding, context: Any) -> float:
        """
        Determine computed confidence score based on evidence validity and WAF status.
        If WAF is enabled on target, we lower the exploitation confidence.
        """
        base_confidence = getattr(finding, "confidence", 1.0)
        
        # If target context has WAF enabled, lower confidence slightly due to blocking potential
        if context and hasattr(context, "profile") and context.profile.waf:
            return round(base_confidence * 0.8, 2)
            
        return base_confidence

    def calculate_risk_score(self, finding: IFinding, context: Any = None) -> float:
        """
        Calculate overall dynamic risk score on a 0-100 scale.
        
        Formula:
          Score = BaseSeverityScore * ConfidenceMultiplier * ExploitabilityMultiplier * (1 - FalsePositiveProbability)
        """
        severity_map = {
            "critical": 100.0,
            "high": 75.0,
            "medium": 50.0,
            "low": 20.0,
            "info": 5.0
        }
        
        sev = str(finding.severity).lower()
        base_score = severity_map.get(sev, 50.0)

        # Extract attributes from finding.evidence if present, otherwise defaults
        evidence = getattr(finding, "evidence", {}) or {}
        extra = {}
        if isinstance(evidence, dict):
            extra = evidence.get("extra", {})
            if not isinstance(extra, dict):
                extra = {}

        confidence = getattr(finding, "confidence", 1.0)
        
        # Determine exploitability modifier [0.1 - 1.0]
        exploitability = 1.0
        if isinstance(evidence, dict):
            exploitability = evidence.get("exploitability", extra.get("exploitability", 1.0))
            
        if context and hasattr(context, "profile") and context.profile.waf:
            # WAF reduces active exploitability
            exploitability *= 0.7
            
        # Determine false positive probability [0.0 - 1.0]
        fp_prob = 0.0
        if isinstance(evidence, dict):
            fp_prob = evidence.get("false_positive_probability", extra.get("false_positive_probability", 0.0))
        
        # Apply formula
        score = base_score * confidence * exploitability * (1.0 - fp_prob)
        
        # Clamp to [0.0, 100.0]
        return max(0.0, min(100.0, round(score, 2)))

    def get_priority_level(self, score: float) -> str:
        """Translate numeric risk score to qualitative level."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 35:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "INFO"
