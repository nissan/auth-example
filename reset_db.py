#!/usr/bin/env python3
"""
Database Reset Script
Clears all users and credentials to allow fresh testing of registration flow.
"""

import os
import sys
from pathlib import Path

def reset_database():
    """Delete the SQLite database file and app.log to start fresh."""
    db_path = Path("app.db")
    log_path = Path("app.log")

    print("🔄 Database Reset Script")
    print("=" * 50)

    # Check if database exists
    if db_path.exists():
        print(f"Found database: {db_path}")
        db_size = db_path.stat().st_size
        print(f"Database size: {db_size} bytes")

        # Delete database
        db_path.unlink()
        print("✅ Database deleted")
    else:
        print("ℹ️  No database file found (already clean)")

    # Check if log exists
    if log_path.exists():
        print(f"\nFound log file: {log_path}")
        log_size = log_path.stat().st_size
        print(f"Log size: {log_size} bytes")

        # Delete log
        log_path.unlink()
        print("✅ Log file deleted")
    else:
        print("ℹ️  No log file found (already clean)")

    print("\n" + "=" * 50)
    print("✨ Database reset complete!")
    print("\nNext steps:")
    print("1. Restart the server: uvicorn main:app --reload")
    print("2. Open http://localhost:8000")
    print("3. Register with TouchID")
    print("\nNote: On first request, the database tables will be")
    print("      automatically recreated by SQLAlchemy.")

if __name__ == "__main__":
    try:
        reset_database()
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
