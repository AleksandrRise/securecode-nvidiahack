"""
PatchFrame - Real-Time Patch-Level Vulnerability Scanner for Open Source Dependencies

A comprehensive security tool that scans dependency trees down to the function/patch level,
comparing git diffs, commit messages, and behavior signatures across releases to detect:
- Introduced vulnerabilities
- Missing patches in current installations
- Suspicious diffs (obfuscated/minified code)
- Untrusted contributors touching critical code
"""

__version__ = "1.0.0"
__author__ = "PatchFrame Team"
__description__ = "Real-Time Patch-Level Vulnerability Scanner" 