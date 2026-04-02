import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

print("====================================")
print("🔍 Checking MySQL Connection...")
print(f"Host: {os.getenv('MYSQL_HOST', 'localhost')}")
print(f"User: {os.getenv('MYSQL_USER', 'root')}")
print(f"Password: {'*' * len(str(os.getenv('MYSQL_PASSWORD', '')))} (Length: {len(str(os.getenv('MYSQL_PASSWORD', '')))})")
print("====================================\n")

try:
    conn = mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASSWORD", "")
    )
    print("✅ SUCCESS! Connected to the MySQL Server!")
    conn.close()
    
    # Check if 'safejob' database exists
    conn2 = mysql.connector.connect(
        host=os.getenv("MYSQL_HOST", "localhost"),
        user=os.getenv("MYSQL_USER", "root"),
        password=os.getenv("MYSQL_PASSWORD", ""),
        database=os.getenv("MYSQL_DATABASE", "safejob")
    )
    print(f"✅ SUCCESS! Database '{os.getenv('MYSQL_DATABASE', 'safejob')}' is active and ready!")
    conn2.close()

except Exception as e:
    print("❌ FAILED TO CONNECT!")
    print(f"\nExact Error Message from MySQL:\n{e}")
    print("\nTroubleshooting:")
    print("1. Are you sure your MySQL software (like XAMPP or MySQL Workbench) is currently 'Running'?")
    print("2. Is the password 'M@uli8056' exactly correct?")
