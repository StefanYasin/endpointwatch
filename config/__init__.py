"""API key resolution for endpointwatch.

Priority order (never commit real keys to this repo):
  1. Environment variables: OPENAI_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
  2. User config: %APPDATA%/endpointwatch/api_keys.json (Windows)
     or ~/.config/endpointwatch/api_keys.json (Linux/macOS)
  3. Local repo file: config/api_keys.json (gitignored, fallback only)
"""
import json
import os
from pathlib import Path

ENV_MAP = {
    "openai": "OPENAI_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
}

USER_CONFIG_PATHS = [
    Path(os.environ.get("APPDATA", "")) / "endpointwatch" / "api_keys.json",
    Path.home() / ".config" / "endpointwatch" / "api_keys.json",
]
LOCAL_CONFIG = Path("config") / "api_keys.json"


def load_api_keys():
    """Return dict of provider -> key following the priority order above."""
    keys = {}

    # Lowest priority first: local repo file
    try:
        if LOCAL_CONFIG.exists():
            keys.update(json.loads(LOCAL_CONFIG.read_text(encoding="utf-8")))
    except Exception:
        pass

    # User config overrides local file
    for path in USER_CONFIG_PATHS:
        try:
            if path.exists():
                keys.update(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            pass

    # Environment variables have the final say
    for provider, env in ENV_MAP.items():
        value = os.environ.get(env)
        if value:
            keys[provider] = value

    return {k: v for k, v in keys.items() if v}
