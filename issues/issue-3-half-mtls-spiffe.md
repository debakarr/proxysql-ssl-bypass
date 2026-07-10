## ProxySQL version
3.0.6 (also confirmed on 2.7.3)

## Description

If a user has `use_ssl=1` and a `spiffe_id` attribute, and an admin later
sets `use_ssl=0` without clearing the SPIFFE identity, ProxySQL continues to
enforce the SPIFFE rule. The result is a generic `Access denied for user`
error that looks like a password/auth problem, when the real cause is that
ProxySQL is trying to extract a SPIFFE identity from a plaintext connection
where none exists.

## Steps to reproduce

Reproduction repo: https://github.com/debakroy/proxysql-ssl-bypass

1. Create a user with `use_ssl=1` and `spiffe_id` in attributes:

```sql
INSERT INTO mysql_users (username, password, active, use_ssl, attributes)
VALUES ('spiffe_user', 'spiffe_password', 1, 1,
        '{"spiffe_id": "spiffe://example.org/ns/default/sa/client"}');
LOAD MYSQL USERS TO RUNTIME;
```

2. Verify the user can connect with a valid SPIFFE client certificate.

3. Simulate an admin disabling SSL but forgetting to clear SPIFFE:

```sql
UPDATE mysql_users SET use_ssl=0 WHERE username='spiffe_user';
LOAD MYSQL USERS TO RUNTIME;
```

4. Attempt a plaintext connection:

```python
import mysql.connector
conn = mysql.connector.connect(
    host='127.0.0.1', port=6033, user='spiffe_user',
    password='spiffe_password', ssl_disabled=True,
)
```

## Expected behavior

Since `use_ssl=0`, plaintext connections should be accepted, or at minimum
the error message should indicate that the SPIFFE rule is still active.

## Actual behavior

```
1045 (28000): ProxySQL Error: Access denied for user 'spiffe_user'
```

A generic `Access denied` misleading administrators into thinking the password
is wrong.

## Suggested fix

Either:
- Automatically clear SPIFFE enforcement when `use_ssl` is set to 0 at the
  ProxySQL level (LOAD MYSQL USERS TO RUNTIME), or
- Return a clearer error like *"SPIFFE identity requires TLS"* when a
  plaintext connection is attempted by a user with `spiffe_id` set.
