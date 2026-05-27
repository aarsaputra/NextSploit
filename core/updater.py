# core/updater.py
import requests
import subprocess
import sys
from core.version import APP_VERSION, APP_REPO
from core.output import log_info, log_warning, log_success

def check_latest_version() -> bool:
    """Check GitHub for latest release version"""
    try:
        # Convert GitHub repo HTML link to standard GitHub API endpoint
        api_url = APP_REPO.replace("github.com", "api.github.com/repos") + "/releases/latest"
        r = requests.get(api_url, timeout=5, headers={"Accept": "application/vnd.github.v3+json"})
        
        if r.status_code == 200:
            latest = r.json().get("tag_name", "").lstrip("v")
            current = APP_VERSION
            
            if latest and latest > current:
                log_warning(f"┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
                log_warning(f"┃  ⚠ UPDATE AVAILABLE: v{current} → v{latest:<28} ┃")
                log_warning(f"┃  🔗 {APP_REPO:<50} ┃")
                log_warning(f"┃  💡 Run: python nextsploit.py --update                 ┃")
                log_warning(f"┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
                return False
            else:
                log_success(f"✓ NextSploit v{current} is up to date.")
                return True
        else:
            log_info(f"Could not check latest version (HTTP status: {r.status_code})")
            return None
    except Exception as e:
        log_info(f"Version check currently unavailable: {e}")
        return None

def run_self_update():
    """Execute git pull and package update"""
    log_info("Starting self-update routine...")
    try:
        # Git pull
        log_info("Running git pull origin main...")
        p_git = subprocess.run(["git", "pull", "origin", "main"], capture_output=True, text=True)
        if p_git.returncode == 0:
            log_success("Git pull succeeded!")
            print(p_git.stdout)
        else:
            log_warning("Git pull returned non-zero code. You might need to merge changes manually.")
            print(p_git.stderr)
            
        # Pip install
        log_info("Updating dependencies from requirements.txt...")
        p_pip = subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"], capture_output=True, text=True)
        if p_pip.returncode == 0:
            log_success("All dependencies updated successfully!")
        else:
            log_warning("Pip package installer failed to run correctly.")
            print(p_pip.stderr)
            
        log_success("Update sequence complete.")
    except Exception as e:
        log_warning(f"Failed to execute self-update sequence: {e}")
