#!/bin/bash

echo "🧩 Starting PatchFrame..."
echo "=========================="

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found. Please run:"
    echo "   python3 -m venv .venv"
    echo "   source .venv/bin/activate"
    echo "   pip install -r requirements-minimal.txt"
    exit 1
fi

# Activate virtual environment
source .venv/bin/activate

# Check if dependencies are installed
if ! python -c "import fastapi, uvicorn" 2>/dev/null; then
    echo "❌ Dependencies not installed. Installing..."
    pip install -r requirements-minimal.txt
fi

# Initialize database if needed
if [ ! -f "patchframe.db" ]; then
    echo "📊 Initializing database..."
    python -c "from patchframe.database.models import init_database; init_database(); print('Database initialized!')"
fi

# Start the server
echo "🚀 Starting PatchFrame API server..."
echo "   Dashboard: http://localhost:8000/static/dashboard.html"
echo "   API Docs:  http://localhost:8000/docs"
echo "   Health:    http://localhost:8000/health"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python run.py 