import mysql.connector
from mysql.connector.errors import Error

HOST = "127.0.0.1"
PORT = 6033
DB = "appdb"


def test_plaintext_to_ssl():
    print("--- TEST: Plaintext Socket to SSL User ---")
    try:
        # 1. Connect initially WITHOUT SSL
        conn = mysql.connector.connect(
            host=HOST,
            port=PORT,
            database=DB,
            user="user_no_ssl",
            password="pass_no_ssl",
        )
        cursor = conn.cursor()
        cursor.execute("SELECT USER(), CURRENT_USER()")
        print("Initial Connection:", cursor.fetchone())

        # 2. Attempt to bypass SSL requirement via COM_CHANGE_USER
        print("Sending COM_CHANGE_USER to 'user_with_ssl'...")
        try:
            conn.cmd_change_user("user_with_ssl", "pass_with_ssl", DB)
            cursor.execute("SELECT USER(), CURRENT_USER()")
            print("After COM_CHANGE_USER:", cursor.fetchone())
        except Error as e:
            print(f"FAILED (Expected if ProxySQL blocks it): {e}")

        conn.close()
    except Error as e:
        print(f"Connection error: {e}")


if __name__ == "__main__":
    test_plaintext_to_ssl()
