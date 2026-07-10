## Description

There is currently no way to require a client certificate for a frontend user
without using the SPIFFE system (`attributes.spiffe_id`), which couples the
requirement to a specific SPIFFE URI. A generic "this user needs a valid
client certificate" flag (analogous to MySQL's `CREATE USER ... REQUIRE X509`)
is missing.

## Use case

An admin wants to enforce that users connecting to ProxySQL present a valid
TLS client certificate, without caring about the specific SPIFFE identity.
Currently the only option is either:

- `use_ssl=1` (accepts any TLS — no client cert needed)
- `use_ssl=1` + `spiffe_id` (requires a specific SPIFFE identity)

There's no middle ground: "any valid client cert is acceptable."

## Proposed solution

Add a new option, for example:

1. A new column `require_client_cert INT DEFAULT 0` in `mysql_users`, or
2. An `attributes` key like `"require_x509": true`

When enabled, ProxySQL requires the frontend connection to present a valid
client certificate signed by a trusted CA, but does not mandate a specific
identity.

Related: issue #4582 (closed without action)
