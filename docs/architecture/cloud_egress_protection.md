# Cloud Egress Protection

Core SIA workflows remain local and make no network calls. When an operator
explicitly sends data to cloud storage or a recipient that supports this
format, `sia.egress.CloudEgressEnvelope` seals the payload before egress.
The module itself performs no I/O.

## Portable envelope

`sia.cloud-egress.v1` is canonical JSON with these fields:

- `schema`: `sia.cloud-egress.v1`
- `suite`: `SIA-E1`, currently AES-256-GCM with Argon2id
- `kdf`: `argon2id`
- `kdf_params`: `{ "iterations": 3, "lanes": 4, "memory_cost": 65536, "length": 32 }`
- `recipient_id` and `content_type`: visible routing metadata, authenticated as
  AES-GCM additional authenticated data
- `created`: ISO-8601 UTC creation time
- `expires`: optional ISO-8601 UTC expiry time; expired envelopes fail closed
- `salt`: 16 random bytes, URL-safe base64
- `nonce`: 12 random bytes, URL-safe base64
- `ciphertext`: AES-GCM ciphertext and 16-byte authentication tag, URL-safe
  base64
- `envelope_id`: SHA-256 of the canonical envelope object excluding
  `envelope_id`

Keys are derived from a user-provided secret and the per-envelope salt. The
secret is never serialized. Recipients must authenticate the exact
`recipient_id`; modified ciphertext or authenticated metadata fails closed.

The envelope has deliberately simple, published primitives so equivalent
implementations can be made in Swift, JavaScript, Go, Rust, or other runtimes.
Recipient identifiers use `provider:`, `vault:`, `device:`, `storage:`, or
`peer:` namespaces. See [SIA Egress Protocol v1](../../RFC/SIA-EP-0001.md) for
the normative wire protocol and interoperability requirements.

## Boundary

CloudEgressEnvelope protects data at rest and during transport to an authorized
recipient. It is not intended to provide end-to-end confidentiality from hosted
inference providers that require plaintext to execute a request. Existing
provider drivers use TLS and only receive authority-approved context; they are
not represented as end-to-end encrypted cloud recipients.
