# 🧩 PatchFrame - Quick Start Guide

## 🚀 Get Started in 30 Seconds

### Option 1: Use the startup script
```bash
./start.sh
```

### Option 2: Manual setup
```bash
# 1. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements-minimal.txt

# 3. Initialize database
python -c "from patchframe.database.models import init_database; init_database()"

# 4. Start server
python run.py
```

## 🌐 Access PatchFrame

Once running, open your browser to:
- **Dashboard**: http://localhost:8000/static/dashboard.html
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 🔧 Run Your First Scan

### Via CLI
```bash
# Scan a project
python -m patchframe.cli.main scan /path/to/your/project

# Scan with options
python -m patchframe.cli.main scan /path/to/your/project --format table --trust-analysis --anomaly-detection
```

### Via API
```bash
# Start a scan
curl -X POST "http://localhost:8000/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"project_path": "/path/to/your/project", "max_commits": 100}'

# Check scan status
curl "http://localhost:8000/api/v1/scans?limit=1"
```

## 📊 What PatchFrame Detects

✅ **Patch-level vulnerabilities** - Analyzes individual git commits  
✅ **Security-relevant commits** - Even without official CVEs  
✅ **Dangerous functions** - eval, Function constructor, etc.  
✅ **Suspicious patterns** - Obfuscated code, minification  
✅ **Trust scoring** - Maintainer reputation analysis  
✅ **Anomaly detection** - Unusual code changes  

## 🎯 Example Results

PatchFrame found **37 vulnerabilities** in a test project:
- **3 Critical** vulnerabilities
- **34 High** severity issues
- Real security patches in lodash, express, and jest

## 🔗 Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check out the [API documentation](http://localhost:8000/docs)
- Explore the interactive dashboard
- Try scanning your own projects!

---

**PatchFrame** - Real-time patch-level vulnerability scanning for open source dependencies 🧩 