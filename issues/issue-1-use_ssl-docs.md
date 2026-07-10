## Description

The documentation at https://proxysql.com/documentation/main-runtime/mysql-tables/#mysql_users
states that `use_ssl` means:

> *"if set to 1, the user is forced to authenticate using an SSL certificate."*

This implies the client must present a TLS certificate (MySQL's `REQUIRE X509`).
The actual behavior is "require TLS encryption on the frontend connection"
(MySQL's `REQUIRE SSL`) — no client certificate is needed.

The SSL Support page (https://proxysql.com/documentation/ssl-support/) uses
different wording:

> *"Enforcing SSL connections is supported in a per-user basis via
> mysql_users.use_ssl configuration option."*

which matches the behavior, but contradicts the `mysql_users` page.

## How to verify

Reproduction repo: https://github.com/debakroy/proxysql-ssl-bypass

Connecting as `user_no_ssl` (use_ssl=0) with `ssl_disabled=False` triggers a
TLS handshake with the ProxySQL server (no client cert presented). Then
`COM_CHANGE_USER` to `user_with_ssl` (use_ssl=1) succeeds:

```
ssl_disabled=False → cipher=TLS_AES_128_GCM_SHA256 → pivot to user_with_ssl: ALLOWED
ssl_disabled=True  → plaintext                      → pivot to user_with_ssl: BLOCKED
```

This proves `use_ssl=1` only checks "is the socket encrypted?" not "did the
client present a cert?"

## Suggested fix

Update the `mysql_users` documentation to:

> **use_ssl** — if set to 1, the frontend connection must use TLS encryption.
> This is equivalent to MySQL's `REQUIRE SSL`. To require a client certificate,
> use the `spiffe_id` attribute in combination with `have_ssl=true`.
