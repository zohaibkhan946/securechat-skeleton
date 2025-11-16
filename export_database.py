#!/usr/bin/env python3
"""Export MySQL database schema and sample data."""

import subprocess
import os
from dotenv import load_dotenv

load_dotenv()


def export_schema():
    """Export database schema only (no data)."""
    db_user = os.getenv("DB_USER", "scuser")
    db_password = os.getenv("DB_PASSWORD", "scpass")
    db_name = os.getenv("DB_NAME", "securechat")
    
    print(f"Exporting schema for database: {db_name}")
    
    # Export schema only
    cmd = [
        "mysqldump",
        f"-u{db_user}",
        f"-p{db_password}",
        "--no-data",  # Schema only
        "--single-transaction",
        "--routines",
        "--triggers",
        db_name
    ]
    
    try:
        with open("schema.sql", "w", encoding="utf-8") as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                print("✓ Schema exported to schema.sql")
                return True
            else:
                print(f"✗ Error exporting schema: {result.stderr}")
                return False
    except FileNotFoundError:
        print("✗ mysqldump not found. Please install MySQL client tools.")
        print("  Alternative: Use MySQL Workbench or phpMyAdmin to export schema.")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def export_sample_data():
    """Export sample data only (no schema)."""
    db_user = os.getenv("DB_USER", "scuser")
    db_password = os.getenv("DB_PASSWORD", "scpass")
    db_name = os.getenv("DB_NAME", "securechat")
    
    print(f"Exporting sample data for database: {db_name}")
    
    # Export data only
    cmd = [
        "mysqldump",
        f"-u{db_user}",
        f"-p{db_password}",
        "--no-create-info",  # Data only
        "--single-transaction",
        db_name
    ]
    
    try:
        with open("sample_data.sql", "w", encoding="utf-8") as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                print("✓ Sample data exported to sample_data.sql")
                print("⚠ WARNING: Do not commit this file if it contains sensitive data.")
                return True
            else:
                print(f"✗ Error exporting data: {result.stderr}")
                return False
    except FileNotFoundError:
        print("✗ mysqldump not found. Please install MySQL client tools.")
        print("  Alternative: Use MySQL Workbench or phpMyAdmin to export data.")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Export MySQL database")
    parser.add_argument("--schema", action="store_true", help="Export schema only")
    parser.add_argument("--data", action="store_true", help="Export sample data only")
    parser.add_argument("--all", action="store_true", help="Export both schema and data")
    
    args = parser.parse_args()
    
    if args.all:
        export_schema()
        export_sample_data()
    elif args.schema:
        export_schema()
    elif args.data:
        export_sample_data()
    else:
        print("Usage:")
        print("  python export_database.py --schema    # Export schema only")
        print("  python export_database.py --data      # Export sample data only")
        print("  python export_database.py --all       # Export both")


if __name__ == "__main__":
    main()
