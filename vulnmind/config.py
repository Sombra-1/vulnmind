"""
config.py — Persistent configuration for VulnMind.

Stores: Groq API key, Enrich license key, and preferences.
Location: ~/.vulnmind/config.json

Why ~/.vulnmind/ and not the project directory?
  - Survives pip reinstalls (project dir gets wiped)
  - Works correctly as root on Kali (~/.vulnmind = /root/.vulnmind)
  - Follows Unix convention for user config (~/.appname/)

The Config class is a simple dict wrapper with typed getters/setters.
We don't use a full config library (like dynaconf or pydantic-settings)
because our needs are minimal — just a handful of keys.
"""

import json
import os
import tempfile
from pathlib import Path


# Where config lives on disk
CONFIG_DIR = Path.home() / ".vulnmind"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Where we cache NVD CVE lookups so we don't hammer the API on every run
CACHE_DIR = CONFIG_DIR / "cache"


class Config:
    """
    Thin wrapper around ~/.vulnmind/config.json.

    Usage:
        cfg = Config.load()
        cfg.set("groq_api_key", "gsk_...")
        cfg.save()
        key = cfg.get("groq_api_key")
    """

    def __init__(self, data: dict):
        self._data = data

    # ------------------------------------------------------------------
    # Load / Save
    # ------------------------------------------------------------------

    @classmethod
    def load(cls) -> "Config":
        """Load config from disk. Returns empty config if file doesn't exist."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (ValueError, OSError):
                # Corrupt or unreadable config — start fresh rather than crashing
                data = {}
            if not isinstance(data, dict):
                data = {}
        else:
            data = {}
        return cls(data)

    def save(self) -> None:
        """Atomically write current config with owner-only permissions."""
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=CONFIG_FILE.parent,
                prefix=f".{CONFIG_FILE.name}.",
                suffix=".tmp",
                delete=False,
            ) as f:
                temp_path = Path(f.name)
                os.chmod(temp_path, 0o600)
                json.dump(self._data, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, CONFIG_FILE)
            temp_path = None
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Getters / Setters
    # ------------------------------------------------------------------

    def get(self, key: str, default=None):
        """Get a config value. Also checks environment variables first.

        Environment variable names are uppercased with VULNMIND_ prefix:
          groq_api_key  →  VULNMIND_GROQ_API_KEY
          license_key   →  VULNMIND_LICENSE_KEY

        This lets CI/CD pipelines and Docker environments pass keys without
        a config file, and lets power users override config without editing JSON.
        """
        env_key = f"VULNMIND_{key.upper()}"
        env_val = os.environ.get(env_key)
        if env_val is not None:
            return env_val
        return self._data.get(key, default)

    def set(self, key: str, value) -> None:
        """Set a config value in memory (call save() to persist)."""
        self._data[key] = value

    def delete(self, key: str) -> None:
        """Remove a config value."""
        self._data.pop(key, None)

    # ------------------------------------------------------------------
    # Typed convenience properties
    # ------------------------------------------------------------------

    @property
    def groq_api_key(self) -> str | None:
        return self.get("groq_api_key")

    @property
    def model(self) -> str:
        """AI model to use. Default is Groq's flagship free-tier model (70B)."""
        return self.get("model", "llama-3.3-70b-versatile")

    @property
    def update_checks_enabled(self) -> bool:
        """Whether normal text output may check GitHub for a new release."""
        value = self.get("update_checks", True)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() not in {
                "0", "false", "off", "no", "disabled",
            }
        return bool(value)

    # ------------------------------------------------------------------
    # Display helper (for `vulnmind config show`)
    # ------------------------------------------------------------------

    def display_dict(self) -> dict:
        """Return config values safe to display — API key is masked."""
        result = {}
        for key, value in self._data.items():
            if "key" in key.lower() and value:
                # Show only first 8 chars of keys: gsk_1234...
                result[key] = (
                    value[:8] + "..."
                    if isinstance(value, str) and len(value) > 8 else "***"
                )
            else:
                result[key] = value
        return result
