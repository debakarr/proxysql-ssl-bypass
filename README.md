# ProxySQL SSL Bypass via `COM_CHANGE_USER`

This repository contains a Proof of Concept (PoC) demonstrating a **Secure Channel Bypass** vulnerability in ProxySQL. 

According to ProxySQL documentation, setting `use_ssl=1` in the `mysql_users` table strictly enforces that the user must connect over a TLS encrypted connection. However, this environment demonstrates that an attacker or client can bypass this restriction by establishing a plaintext connection with a non-SSL user and subsequently issuing a `COM_CHANGE_USER` command to pivot to the SSL-enforced user. ProxySQL fails to re-validate the TLS state of the inherited socket, leaving the connection entirely unencrypted.

## 🛠️ Prerequisites

* **Docker & Docker Compose:** To run the database and ProxySQL containers.
* **Python 3.13+:** For running the test script.
* **[uv](https://docs.astral.sh/uv/):** The Python package manager used in this repository.

## 📁 Repository Structure

* `test.py`: The Python PoC script that performs the SSL bypass.
* `proxysql.cnf`: The ProxySQL configuration defining our users (`user_no_ssl` and `user_with_ssl`).
* `init.sql`: The backend MySQL database provisioning script.
* `certs/`: Pre-generated self-signed certificates used by ProxySQL.
* **Docker Compose Files** (Testing different architecture stacks):
    * `old-compose.yml`: Percona Server 8.0.35 + Percona ProxySQL 2.7.3
    * `new-compose.yml`: Percona Server 8.4 + Percona ProxySQL 3.0.6

## 🚀 How to Reproduce

### 1. Start the Environment
Choose one of the provided Docker Compose files and spin up the stack. For example, to test the ProxySQL 3.x / Percona 8.4 stack:

```bash
docker compose -f new-compose.yml up -d

```

### 2. Wait for Database Initialization ⚠️ IMPORTANT

If this is the first time you are booting the stack, the backend MySQL container must build its initial data directory. **This takes about 20-30 seconds.** If you run the test before the backend is fully initialized, ProxySQL will drop your connection with a `system error: 2`.

You can tail the logs to watch the boot process:

```bash
docker compose -f new-compose.yml logs -f percona-mysql

```

*Wait until you see a log entry indicating the server is `ready for connections`, then press `Ctrl+C`.*

### 3. Verify ProxySQL State

Ensure ProxySQL has successfully connected to the backend. Run this command to query ProxySQL's internal admin interface:

```bash
docker compose -f new-compose.yml exec proxysql mysql -u admin -padmin -h 127.0.0.1 -P 6032 -e "SELECT hostgroup_id, hostname, status FROM mysql_servers;"

```

*The status must show `ONLINE`. If it shows `SHUNNED`, wait a few more seconds and try again.*

### 4. Execute the Exploit

Run the Python script using `uv`:

```bash
uv run test.py

```

### Expected Output

If the vulnerability is present, the script will successfully connect over a plaintext socket, pivot to the SSL-enforced user, and output the following:

```text
--- TEST: Plaintext Socket to SSL User ---
Initial Connection: ('user_no_ssl@...', 'user_no_ssl@%')
Sending COM_CHANGE_USER to 'user_with_ssl'...
After COM_CHANGE_USER: ('user_with_ssl@...', 'user_with_ssl@%')

```

## 🧹 Cleanup

To tear down the environment and wipe the database volumes, run:

```bash
docker compose -f new-compose.yml down -v

```

*(Replace `new-compose.yml` with the specific file you tested).*

