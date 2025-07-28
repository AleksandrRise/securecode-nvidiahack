#!/usr/bin/env python3
"""
Simple script to run the PatchFrame API server.
"""

import uvicorn
import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """Run the PatchFrame API server."""
    # Default configuration
    host = os.getenv("PATCHFRAME_HOST", "0.0.0.0")
    port = int(os.getenv("PATCHFRAME_PORT", "8000"))
    reload = os.getenv("PATCHFRAME_RELOAD", "false").lower() == "true"
    
    print(f"🧩 Starting PatchFrame API server...")
    print(f"   Host: {host}")
    print(f"   Port: {port}")
    print(f"   Reload: {reload}")
    print(f"   Dashboard: http://{host}:{port}/static/dashboard.html")
    print(f"   API Docs: http://{host}:{port}/docs")
    print()
    
    try:
        uvicorn.run(
            "patchframe.api.main:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 