#!/bin/bash

echo "🧩 PatchFrame Demo"
echo "=================="

# Activate virtual environment
source .venv/bin/activate

echo ""
echo "1. 📊 Running a scan on the test project..."
python -m patchframe.cli.main scan test-project --format summary

echo ""
echo "2. 🌐 Starting the API server..."
echo "   Dashboard will be available at: http://localhost:8000/static/dashboard.html"
echo "   API documentation at: http://localhost:8000/docs"
echo ""
echo "3. 📈 The dashboard will show:"
echo "   - Real-time vulnerability analysis"
echo "   - Patch-level security scanning"
echo "   - Trust scoring and anomaly detection"
echo "   - Interactive visualizations"
echo ""
echo "4. 🔧 You can also use the CLI:"
echo "   python -m patchframe.cli.main scan <project-path>"
echo "   python -m patchframe.cli.main trust <dependency> <patch-sha>"
echo "   python -m patchframe.cli.main anomaly <dependency> <patch-sha>"
echo ""
echo "5. 🚀 Or use the API:"
echo "   curl -X POST http://localhost:8000/api/v1/scan"
echo "   curl http://localhost:8000/api/v1/scans"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python run.py 