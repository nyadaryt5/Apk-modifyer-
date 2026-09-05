#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
# OmniAPK Studio - 1-Click Android Termux Installer & Launcher
# Optimized for mobile execution with zero-root requirements for pure mods
# ==============================================================================

set -e

echo "📱 [OmniAPK Mobile] Installing OmniAPK Studio for Android (Termux)..."

# Update package repository and install basic packages in Termux
pkg update -y || apt-get update -y
pkg install -y python python-pip openssl git || true

# Install Python requirements
echo "[*] Installing Python dependencies in Termux environment..."
pip install -r requirements.txt

# Grant executable permissions
chmod +x cli.py
chmod +x main.py

# Create termux shortcut command
mkdir -p "$PREFIX/bin"
ln -sf "$(pwd)/cli.py" "$PREFIX/bin/omniapk" || cp cli.py "$PREFIX/bin/omniapk"
ln -sf "$(pwd)/cli.py" "$PREFIX/bin/apkmod" || cp cli.py "$PREFIX/bin/apkmod"

# Generate test sample
python3 samples/make_sample_apk.py

echo ""
echo "=============================================================================="
echo "  📱 ✓ OmniAPK Studio is ready on Android (Termux)!"
echo ""
echo "  To launch Mobile Web Studio on your phone:"
echo "    python3 main.py"
echo "    Then open your browser at: http://localhost:8000"
echo ""
echo "  To run CLI on Android:"
echo "    omniapk lucky-patch target.apk"
echo "    omniapk ai-mod target.apk --prompt 'Unlock VIP and strip ads'"
echo "=============================================================================="
