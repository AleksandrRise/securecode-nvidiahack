"""
Setup script for PatchFrame.
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="patchframe",
    version="1.0.0",
    author="PatchFrame Team",
    author_email="support@patchframe.io",
    description="Real-Time Patch-Level Vulnerability Scanner for Open Source Dependencies",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/patchframe",
    project_urls={
        "Bug Tracker": "https://github.com/your-org/patchframe/issues",
        "Documentation": "https://docs.patchframe.io",
        "Source Code": "https://github.com/your-org/patchframe",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "bandit>=1.7.0",
            "safety>=2.3.0",
        ],
        "api": [
            "uvicorn[standard]>=0.24.0",
            "gunicorn>=21.0.0",
        ],
        "database": [
            "psycopg2-binary>=2.9.0",
            "redis>=5.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "patchframe=patchframe.cli.main:app",
        ],
    },
    include_package_data=True,
    package_data={
        "patchframe": [
            "static/*",
            "templates/*",
        ],
    },
    keywords=[
        "security",
        "vulnerability",
        "scanner",
        "dependencies",
        "patches",
        "git",
        "ast",
        "sbom",
        "trust",
        "anomaly",
    ],
    platforms=["any"],
    zip_safe=False,
) 