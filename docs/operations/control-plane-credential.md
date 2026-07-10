# Control-plane credential

The Relay's control-plane listener (MCP + `/api/v1`, ADR-0009/0010) is protected by a single
seeded bearer credential (the "founding admin" credential). This is the staged, pre-Account
authz model (ADR-0010): one vault-managed credential today, the first admin Account in
v0.3.0.

The Relay never sees or stores the plaintext credential. It stores only the credential's
SHA-256 hash, in the canonical form:

```
sha256:<64 lowercase hex characters>
```

That hash lives in a root-owned file on disk (path given by
`-control-credential-hash-file` / `RELAY_CONTROL_CREDENTIAL_HASH_FILE`); the plaintext lives
only in the operator's secret store (e.g. Ansible Vault). If the control-plane listener is
enabled (`-control-enabled` / `RELAY_CONTROL_ENABLED`) and the hash file is missing or
malformed, the Relay refuses to start rather than serve an unauthenticated or
misconfigured control plane.

## Generating the hash

Pick a high-entropy plaintext credential (treat it like any other machine bearer token —
e.g. 32+ random bytes, base64 or hex encoded) and hash it with **one** of:

### `relay hash-credential`

Reads the plaintext from stdin only — never a command-line argument or an environment
variable, so it never lands in shell history, a process listing, or a CI log — and prints
the canonical `sha256:<hex>` form:

```console
$ printf '%s' "$CONTROL_PLANE_CREDENTIAL" | relay hash-credential
sha256:7afb4c3889fd608668a69adf181c4218fb70bee515c2320bbc828839a3989fc2
```

### `openssl` / `sha256sum` (no build required)

Equivalent one-liners, useful before a `relay` binary is available or from an unrelated
host:

```console
$ printf '%s' "$CONTROL_PLANE_CREDENTIAL" | openssl dgst -sha256 -r | awk '{print "sha256:" $1}'
$ printf '%s' "$CONTROL_PLANE_CREDENTIAL" | sha256sum | awk '{print "sha256:" $1}'
```

`printf '%s'` (not `echo`) avoids an accidental trailing newline changing the hash; both
one-liners above match what `relay hash-credential` computes for the same input.

## Writing the hash file

Write the `sha256:<hex>` line to a root-owned, non-world-readable file:

```console
$ echo "sha256:7afb4c3889fd608668a69adf181c4218fb70bee515c2320bbc828839a3989fc2" > /etc/relay/control-credential-hash
$ chown root:root /etc/relay/control-credential-hash
$ chmod 0400 /etc/relay/control-credential-hash
```

Then point the Relay at it:

```console
$ relay -control-enabled -control-addr :9443 \
    -control-credential-hash-file /etc/relay/control-credential-hash
```

or the equivalent environment variables:

```console
RELAY_CONTROL_ENABLED=true
RELAY_CONTROL_ADDR=:9443
RELAY_CONTROL_CREDENTIAL_HASH_FILE=/etc/relay/control-credential-hash
```

The plaintext credential itself is presented per-request as a bearer token:

```console
$ curl -H "Authorization: Bearer $CONTROL_PLANE_CREDENTIAL" https://relay.example:9443/api/v1/ping
```

## Rotation and recovery

Rotation is: mint a new plaintext credential, hash it, overwrite the hash file, restart the
Relay. Recovery from a lost plaintext credential is the same procedure — there is no way to
recover the plaintext from the stored hash, by design. Both are file-and-restart operations
owned by IaC (e.g. re-running the Ansible playbook that manages `/etc/relay/`), matching the
"config is a root-owned local file, never reachable over the API" rule (ADR-0010).

## Why SHA-256, not a password KDF

The seeded credential is high-entropy, machine-generated bearer-token material — the same
shape as an Enrollment Token secret (see `relay/internal/enroll/token.go`) — not a
low-entropy human password. A fast cryptographic hash compared in constant time
(`crypto/subtle.ConstantTimeCompare`) is the correct, standard choice for that shape of
secret; slow KDFs like bcrypt/argon2 exist to defend against brute-forcing low-entropy human
secrets and are not needed here. The Relay's local human-login credential model (Admin
Console, v0.3.0+) is a separate, future concern and may make a different choice.
