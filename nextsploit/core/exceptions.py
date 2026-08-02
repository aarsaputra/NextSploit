"""
nextsploit/core/exceptions.py — Custom Exceptions for NextSploit.
"""

class NextSploitException(Exception):
    """Base exception for all NextSploit errors."""
    pass


class ConfigurationException(NextSploitException):
    """Raised when configuration parsing or validation fails."""
    pass


class PipelineException(NextSploitException):
    """Raised when pipeline phase execution or state transitions fail."""
    pass


class PluginException(NextSploitException):
    """Raised when plugin validation, loading, or resolution fails."""
    pass


class PolicyException(NextSploitException):
    """Raised when security policies cannot be resolved or parsed."""
    pass


class DependencyException(NextSploitException):
    """Raised when module or capability dependency conditions are violated."""
    pass
