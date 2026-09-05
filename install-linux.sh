#!/usr/bin/env bash
# ==============================================================================
# OmniAPK Studio - 1-Click Linux Installer & Runner
# For Ubuntu, Debian, Arch, Fedora, Kali, WSL, Headless Servers
# ==============================================================================

set -e

echo "⚡ [OmniAPK] Installing OmniAPK Studio for Linux..."

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[-] Python 3 not found. Please install python3 (e.g. sudo apt install python3 python3-pip)"
    exit 1
fi

# Install required Python packages
echo "[*] Installing Python dependencies..."
python3 -m pip install --break-system-packages -r requirements.txt || pip install -r requirements.txt

# Make CLI executable
chmod +x cli.py
chmod +x main.py

# Create symlink for global CLI command if permissions allow
if [ -w "/usr/local/bin" ]; then
    ln -sf "$(pwd)/cli.py" /usr/local/bin/omniapk
    ln -sf "$(pwd)/cli.py" /usr/local/bin/apkmod
    echo "[✓] Symlinks created: 'omniapk' and 'apkmod' CLI commands are now available globally."
fi

# Generate sample APK for immediate testing
python3 samples/make_sample_apk.py

echo ""
echo "=============================================================================="
echo "  ✓ OmniAPK Studio installed successfully!"
echo "  Run Web Studio:    python3 main.py"
echo "  Run CLI Suite:     ./cli.py --help"
echo "  Run AI Agent:      ./cli.py ai-mod samples/sample_target.apk --prompt 'Unlock VIP and remove ads'"
echo "=============================================================================="
