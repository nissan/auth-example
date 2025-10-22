#!/bin/bash
# Quick reset script - stops server, clears DB, restarts server

echo "🛑 Stopping any running servers..."
lsof -ti:8000 | xargs kill -9 2>/dev/null || echo "No server running on port 8000"

echo ""
python3 reset_db.py

echo ""
echo "🚀 Starting server..."
source .venv/bin/activate 2>/dev/null || true
uvicorn main:app --reload
