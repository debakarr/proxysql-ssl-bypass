# ProxySQL SSL Behavior Analysis

This repository contains scripts demonstrating two findings in ProxySQL
regarding TLS enforcement and identity management.

### 1. `use_ssl` documentation vs behavior

According to the docs, `mysql_users.use_ssl=1` means the user is "forced to
authenticate using an SSL certificate." In practice it behaves like MySQL's
`REQUIRE SSL` (TLS encryption required), not `REQUIRE X509` (client cert
required). No client certificate is needed to connect as a `use_ssl=1` user —
only a TLS-encrypted socket.

### 2. Half-mTLS State (Stale SPIFFE Identity)

Flipping `use_ssl` to `0` on a user does **not** clear their SPIFFE identity
attributes dynamically. The proxy continues enforcing the SPIFFE rule even
though the connection is now expected to be plaintext. This causes the
connection to fail with a generic `Access denied` error, easily misdiagnosed
as an authentication failure rather than a stale mTLS state.

## Prerequisites

- **Docker & Docker Compose:** To run the backend and proxy containers.
- **Python 3.13+:** For running the test script.
- **[uv](https://docs.astral.sh/uv/):** The Python package manager.
- **Make:** For using the provided Makefile automation.
- **OpenSSL:** For generating fresh TLS certificates.

## Repository Structure

- `Makefile`: Automation for spinning up, testing, and certificate generation.
- `test.py`: The Python test script.
- `proxysql.cnf`: ProxySQL configuration defining users.
- `init.sql`: Backend MySQL database provisioning script.
- `certs/`: Directory containing TLS certificates.
- **Docker Compose Files**:
  - `old-compose.yml`: Percona Server 8.0.35 + Percona ProxySQL 2.7.3
  - `new-compose.yml`: Percona Server 8.4 + Percona ProxySQL 3.0.6

## How to Reproduce

Replace `-new` with `-old` in the commands below to test the legacy stack.

### 1. Generate Certificates

```bash
make generate-certs
```

### 2. Start the Stack

```bash
make up-new
```

### 3. Run Tests

```bash
make test
```

### 4. Tear Down

```bash
make down-new
```

## Notes

- **certs/** is in `.gitignore`. The first commit included example certs; run
  `make generate-certs` to create fresh ones for your environment.

## Filed Issues

Drafts for upstream ProxySQL issues are in `issues/`:

- `issue-1-use_ssl-docs.md` — Documentation: `use_ssl` description is misleading
- `issue-2-require-x509-feature.md` — Feature: `REQUIRE X509` equivalent
- `issue-3-half-mtls-spiffe.md` — Bug: Stale SPIFFE identity after toggling `use_ssl`
