# ProxySQL Security Proof of Concepts

This repository contains Proof of Concept (PoC) scripts demonstrating two specific security behaviors/flaws in ProxySQL regarding TLS enforcement and identity management.

### 1. SSL Bypass via `COM_CHANGE_USER`
According to ProxySQL documentation, setting `use_ssl=1` strictly enforces TLS connections for that user. However, this environment demonstrates that an attacker/client can establish a plaintext connection using a non-SSL user and subsequently issue a `COM_CHANGE_USER` command to pivot to the SSL-enforced user. ProxySQL fails to re-validate the TLS state of the inherited socket, leaving the connection entirely unencrypted.

### 2. Half-mTLS State (Stale SPIFFE Identity)
Flipping `use_ssl` to `0` on a user does **not** clear their SPIFFE identity attributes dynamically. The proxy continues enforcing the SPIFFE rule even though the connection is now expected to be plaintext. This causes the connection to fail with a generic "Access denied" error, which is easily misdiagnosed as an authentication failure rather than a stale mTLS state.

## 🛠️ Prerequisites

* **Docker & Docker Compose:** To run the backend and proxy containers.
* **Python 3.13+:** For running the test script.
* **[uv](https://docs.astral.sh/uv/):** The Python package manager.
* **Make:** For using the provided Makefile automation.
* **OpenSSL:** For generating fresh TLS certificates.

## 📁 Repository Structure

* `Makefile`: Automation commands for spinning up, testing, and certificate generation.
* `test.py`: The Python PoC script that executes both tests.
* `proxysql.cnf`: The ProxySQL configuration defining our users.
* `init.sql`: The backend MySQL database provisioning script.
* `certs/`: Directory containing certificates used by ProxySQL.
* **Docker Compose Files**:
    * `old-compose.yml`: Percona Server 8.0.35 + Percona ProxySQL 2.7.3
    * `new-compose.yml`: Percona Server 8.4 + Percona ProxySQL 3.0.6

## 🚀 How to Reproduce

We use a `Makefile` to simplify interacting with the environment. Replace `-new` with `-old` in the commands below to test the legacy stack.

### 1. Generate Certificates
Before bringing up the environment for the first time, generate the TLS certificates. This creates a CA, a Server cert (for ProxySQL), and Client certs (if strict mutual TLS testing is desired):
```bash
make generate-certs
