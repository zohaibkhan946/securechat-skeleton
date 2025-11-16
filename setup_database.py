#!/usr/bin/env python3
"""Setup database with user-provided credentials."""

import pymysql
import sys


def setup_database(host, port, root_user, root_password, db_name, app_user, app_password):
    """Set up database and user."""
    try:
        # Connect as root
        print(f"Connecting to MySQL as {root_user}...")
        root_conn = pymysql.connect(
            host=host,
            port=port,
            user=root_user,
            password=root_password
        )
        
        with root_conn.cursor() as cursor:
            # Create database if not exists
            print(f"Creating database {db_name}...")
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            
            # Create user if not exists
            print(f"Creating user {app_user}...")
            try:
                cursor.execute(f"CREATE USER IF NOT EXISTS '{app_user}'@'localhost' IDENTIFIED BY '{app_password}'")
            except:
                # User might already exist, try to update password
                cursor.execute(f"ALTER USER '{app_user}'@'localhost' IDENTIFIED BY '{app_password}'")
            
            # Grant privileges
            print(f"Granting privileges to {app_user}...")
            cursor.execute(f"GRANT ALL PRIVILEGES ON {db_name}.* TO '{app_user}'@'localhost'")
            cursor.execute("FLUSH PRIVILEGES")
        
        root_conn.commit()
        root_conn.close()
        
        print("✓ Database and user created successfully!")
        
        # Test connection with app user
        print(f"Testing connection as {app_user}...")
        app_conn = pymysql.connect(
            host=host,
            port=port,
            user=app_user,
            password=app_password,
            database=db_name
        )
        app_conn.close()
        print("✓ Connection test successful!")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("Database Setup")
    print("=" * 60)
    print()
    
    if len(sys.argv) >= 7:
        host = sys.argv[1]
        port = int(sys.argv[2])
        root_user = sys.argv[3]
        root_password = sys.argv[4]
        db_name = sys.argv[5]
        app_user = sys.argv[6]
        app_password = sys.argv[7] if len(sys.argv) > 7 else sys.argv[6]
    else:
        print("Usage: python setup_database.py <host> <port> <root_user> <root_password> <db_name> <app_user> [app_password]")
        print("\nExample:")
        print("  python setup_database.py localhost 3306 root mypassword securechat scuser scpass")
        sys.exit(1)
    
    success = setup_database(host, port, root_user, root_password, db_name, app_user, app_password)
    sys.exit(0 if success else 1)
