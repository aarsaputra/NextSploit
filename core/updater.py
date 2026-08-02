#!/usr/bin/env python3
"""
NextSploit — Update Checker
Checks GitHub for newer releases/tags with a 6-hour TTL cache to avoid
spamming the API on every scan invocation.
"""

import json
import os
import subprocess
import sys
import time

import requests

from core.version import APP_VERSION, APP_REPO
from core.output import log_info, log_warning, log_success

# Cache file lives next to this module in the package directory
_CACHE_FILE = os.path.join(os.path.dirname(__file__), ".update_cache.json")
_CACHE_TTL_SECONDS = 6 * 3600  # 6 hours


def _read_cache() -> dict | None:
    """Return cached data if still within TTL, else None."""
    try:
        if not os.path.exists(_CACHE_FILE):
            return None
        with open(_CACHE_FILE) as f:
            data = json.load(f)
        if time.time() - data.get("timestamp", 0) < _CACHE_TTL_SECONDS:
            return data
    except Exception:
        pass
    return None


def _write_cache(tag: str | None) -> None:
    """Persist result so the next run within TTL skips the API call."""
    try:
        with open(_CACHE_FILE, "w") as f:
            json.dump({"timestamp": time.time(), "latest_tag": tag}, f)
    except Exception:
        pass


def _fetch_latest_tag() -> str | None:
    """
    Attempt to resolve the latest version from GitHub:
    1. /releases/latest  (works if formal GitHub Releases exist)
    2. /tags             (fallback — always works if there are git tags)
    Returns the tag string (e.g. "v2.3.0") or None on failure.
    """
    base = APP_REPO.replace("github.com", "api.github.com/repos")
    headers = {"Accept": "application/vnd.github.v3+json"}

    # Strategy 1 — formal releases
    try:
        r = requests.get(f"{base}/releases/latest", timeout=5, headers=headers)
        if r.status_code == 200:
            return r.json().get("tag_name")
    except Exception:
        pass

    # Strategy 2 — git tags (always present even without a formal Release)
    try:
        r = requests.get(f"{base}/tags", timeout=5, headers=headers)
        if r.status_code == 200:
            tags = r.json()
            if tags:
                return tags[0]["name"]
    except Exception:
        pass

    return None  # Both strategies failed — return None silently


def check_latest_version() -> bool | None:
    """
    Check GitHub for a newer version.
    Returns True  if up-to-date,
            False if an update is available,
            None  if the check could not be completed.
    Prints nothing on failure to avoid polluting scan output.
    """
    # --- Use cached result if still fresh ---
    cached = _read_cache()
    if cached is not None:
        latest_tag = cached.get("latest_tag")
    else:
        latest_tag = _fetch_latest_tag()
        _write_cache(latest_tag)

    if latest_tag is None:
        # Silently skip — do not print an error; just move on
        return None

    latest = latest_tag.lstrip("v")
    current = APP_VERSION

    try:
        latest_parts  = [int(x) for x in latest.split(".")]
        current_parts = [int(x) for x in current.split(".")]
        # Pad to equal length
        n = max(len(latest_parts), len(current_parts))
        latest_parts  += [0] * (n - len(latest_parts))
        current_parts += [0] * (n - len(current_parts))

        if latest_parts > current_parts:
            log_warning(f"┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
            log_warning(f"┃  ⚠ UPDATE AVAILABLE: v{current} → v{latest:<28} ┃")
            log_warning(f"┃  🔗 {APP_REPO:<50} ┃")
            log_warning(f"┃  💡 Run: python nextsploit.py --update                 ┃")
            log_warning(f"┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
            return False
        else:
            log_success(f"✓ NextSploit v{current} is up to date.")
            return True
    except (ValueError, AttributeError):
        return None


def run_self_update() -> None:
    """Execute git pull and pip install -r requirements.txt."""
    if sys.stdin.isatty():
        log_warning("⚠️  WARNING: Self-update will execute 'git pull origin main' and 'pip install -r requirements.txt'")
        log_warning("This may overwrite local modifications and upgrade dependencies.")
        try:
            choice = input("Do you want to proceed? [y/N]: ").strip().lower()
            if choice not in ("y", "yes"):
                log_info("Update cancelled by user.")
                return
        except (KeyboardInterrupt, EOFError):
            print()
            log_info("Update cancelled.")
            return

    log_info("Starting self-update routine...")
    try:
        log_info("Running git pull origin main...")
        p_git = subprocess.run(
            ["git", "pull", "origin", "main"],
            capture_output=True, text=True,
        )
        if p_git.returncode == 0:
            log_success("Git pull succeeded!")
            print(p_git.stdout)
        else:
            log_warning("Git pull returned non-zero code — may need manual merge.")
            print(p_git.stderr)

        if not os.path.exists("requirements.txt"):
            log_warning("requirements.txt not found — skipping dependencies install.")
            _write_cache(None)
            log_success("Update sequence complete.")
            return

        log_info("Updating dependencies from requirements.txt...")
        p_pip = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"],
            capture_output=True, text=True,
        )
        if p_pip.returncode == 0:
            log_success("All dependencies updated successfully!")
        else:
            log_warning("pip installer failed.")
            print(p_pip.stderr)

        # Invalidate the update cache so the next run fetches fresh data
        _write_cache(None)
        log_success("Update sequence complete.")
    except Exception as e:
        log_warning(f"Failed to execute self-update sequence: {e}")
