"""
OmniAPK Studio & AI Suite - Main Server Runner.
"""

import sys
import os
import uvicorn
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from omniapk.config import DEFAULT_HOST, DEFAULT_PORT
from omniapk.server.app import app

def main():
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    host = os.environ.get("HOST", DEFAULT_HOST)
    print(f"==================================================")
    print(f"  ⚡ OmniAPK Studio & AI Suite v2.0.0")
    print(f"  8-in-1 Modding Engine for Linux & Android")
    print(f"  Server listening on http://{host}:{port}")
    print(f"==================================================")
    uvicorn.run(app, host=host, port=port, log_level="info")

if __name__ == "__main__":
    main()
