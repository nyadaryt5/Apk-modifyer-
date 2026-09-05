"""
OmniAPK Configuration and Platform Environment
Detects environment (Linux / Android Termux / WSL / macOS) and available system tools.
"""

import os
import sys
import shutil
import platform
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = BASE_DIR / "workspace"
SAMPLES_DIR = BASE_DIR / "samples"
CONFIG_DIR = BASE_DIR / "data"
UPLOAD_DIR = WORKSPACE_DIR / "uploads"
OUTPUT_DIR = WORKSPACE_DIR / "output"
DECOMPILE_DIR = WORKSPACE_DIR / "decompiled"
KEYS_DIR = BASE_DIR / "data" / "keys"

# Ensure runtime directories exist
for directory in [WORKSPACE_DIR, CONFIG_DIR, UPLOAD_DIR, OUTPUT_DIR, DECOMPILE_DIR, KEYS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Platform Detection
def is_android_termux() -> bool:
    """Check if running in Android Termux environment."""
    return "com.termux" in os.environ.get("PREFIX", "") or "TERMUX_VERSION" in os.environ or os.path.exists("/data/data/com.termux")

def is_linux() -> bool:
    """Check if running on Linux-based OS."""
    return sys.platform.startswith("linux")

def get_platform_info() -> dict:
    """Get system and runtime platform diagnostic information."""
    is_termux = is_android_termux()
    return {
        "platform": "Android (Termux)" if is_termux else f"Linux ({platform.system()} {platform.release()})",
        "system": platform.system(),
        "arch": platform.machine(),
        "python_version": platform.python_version(),
        "is_termux": is_termux,
        "is_linux": is_linux(),
        "tools": detect_system_tools()
    }

def detect_system_tools() -> dict:
    """Detect available native and external reverse engineering binaries."""
    tools = {
        "java": shutil.which("java"),
        "javac": shutil.which("javac"),
        "apktool": shutil.which("apktool"),
        "jadx": shutil.which("jadx"),
        "aapt": shutil.which("aapt") or shutil.which("aapt2"),
        "zipalign": shutil.which("zipalign"),
        "apksigner": shutil.which("apksigner"),
        "frida": shutil.which("frida"),
        "adb": shutil.which("adb"),
        "d8": shutil.which("d8") or shutil.which("dx"),
        "baksmali": shutil.which("baksmali"),
        "smali": shutil.which("smali")
    }
    return {k: v for k, v in tools.items() if v is not None}

# Default App Settings
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = int(os.environ.get("PORT", "8000"))
AI_CONFIG_FILE = CONFIG_DIR / "ai_config.json"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
