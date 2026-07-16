# Cloud Egress Protection

Core SIA workflows remain local and make no network calls. When an operator
explicitly sends data to cloud storage or a recipient that supports this
format, `sia.egress.CloudEgressEnvelope` seals the payload before egress.
The module itself performs no I/O.

## Portable envelope

`sia.cloud-egress.v1` is canonical JSON with these fields:

- `schema`: `sia.cloud-egress.v1`
- `kdf`: `scrypt` (`N=32768`, `r=8`, `p=1`, 32-byte output)
- `cipher`: `aes-256-gcm`
- `recipient_id` and `content_type`: visible routing metadata, authenticated as
  AES-GCM additional authenticated data
- `salt`: 16 random bytes, URL-safe base64
- `nonce`: 12 random bytes, URL-safe base64
- `ciphertext`: AES-GCM ciphertext and 16-byte authentication tag, URL-safe
  base64

Keys are derived from a user-provided secret and the per-envelope salt. The
secret is never serialized. Recipients must authenticate the exact
`recipient_id`; modified ciphertext or authenticated metadata fails closed.

The envelope has deliberately simple, published primitives so equivalent
implementations can be made in Swift, JavaScript, Go, Rust, or other runtimes.

## Boundary

This format protects data sent to storage or a recipient that can decrypt it.
It cannot conceal a prompt from a hosted inference provider that must read the
prompt to perform inference. Existing provider drivers use TLS and only receive
authority-approved context; they are not represented as end-to-end encrypted
cloud recipients.
