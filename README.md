# Cipher

Cryptography building blocks for .NET: authenticated encryption, hashing, password hashing, HMAC, versioned key management with rotation, and JWT signing. It is the foundation the other packages in this set build on, and it has no dependency on any of them.

Use it when you need to encrypt data at rest, hash passwords, sign or verify messages, or issue and validate tokens, and you want key rotation to be safe by default.

## Install

```bash
dotnet add package Cipher
```

Packages are published to GitHub Packages; see `nuget.config` for the feed setup.

## Quick start

```csharp
services.AddCipher(o => o.PasswordHashIterations = 210_000);

await keys.RotateAsync("data");                                   // creates version 1 of the key "data"
byte[] sealed = await enc.EncryptAsync("data", plaintext, associatedData: tenantIdBytes);
byte[] opened = await enc.DecryptAsync("data", sealed, associatedData: tenantIdBytes);
```

Registering your own `IKeyStore` before `AddCipher` replaces the default in-memory one, for example with a vault-backed store. Keep is built on Cipher for this reason.

## Keys

`IKeyStore` holds named, versioned keys.

- `RotateAsync("name")` creates the next version, makes it the active one, and retires the previous version. Retired versions can still decrypt and verify, but are no longer used to encrypt or sign.
- `RevokeAsync` makes a version unusable everywhere.
- Key kinds: a symmetric key (AES-256, HMAC, and HS256 tokens) or `KeyKind.EcdsaP256` (ES256 tokens).

```csharp
await keys.RotateAsync("data");
await keys.RotateAsync("sessions", KeyKind.EcdsaP256);
```

Cipher never persists key material itself. The default `InMemoryKeyStore` is for development and tests.

## Encryption (AES-256-GCM)

```csharp
byte[] env   = await enc.EncryptAsync("data", plaintext, associatedData: tenantIdBytes);
byte[] plain = await enc.DecryptAsync("data", env, associatedData: tenantIdBytes);
byte[] moved = await enc.ReEncryptAsync("data", env, tenantIdBytes);   // upgrade to the newest key version
```

- The envelope records which key version encrypted it, so rotating a key never strands old data. Use `ReEncryptAsync` to migrate lazily.
- **Associated data** binds the ciphertext to a context (tenant id, record id). Decrypting with different associated data fails, which stops ciphertexts being swapped between rows or tenants.
- Envelope layout: `[0x01][int32 key version][12-byte nonce][16-byte tag][ciphertext]`. The leading format byte leaves room for future algorithms.
- Nonces are random 96-bit values. Rotate keys well before a single key version encrypts billions of messages.

## Hashing

- `IHashService`: SHA-256, SHA-384 and SHA-512 over bytes or streams, plus constant-time comparison.
- `IPasswordHasher`: PBKDF2-HMAC-SHA512 with a self-describing format (`$qbx-pbkdf2-sha512$iterations$salt$hash`).

```csharp
var hash = hasher.Hash("correct horse battery staple");
bool ok  = hasher.Verify(hash, candidate);
if (ok && hasher.NeedsRehash(hash)) { /* store hasher.Hash(candidate) after you raise the iteration count */ }
```

`Verify` returns `false` for bad input instead of throwing.

## HMAC

`IHmacService.SignAsync` and `VerifyAsync` use versioned keys from the key store. The stateless `Sign` and `Verify` overloads take a secret you fetched elsewhere, for example from Keep. Verification is always constant-time.

## JWT

```csharp
var token  = await jwt.CreateAsync("sessions", new JwtDescriptor { Issuer = "app", Subject = "u1", Lifetime = TimeSpan.FromMinutes(15) });
var result = await jwt.ValidateAsync(token, new JwtValidationOptions { ValidIssuer = "app" });
```

- The signing algorithm comes from the stored key, never from the token header: symmetric keys sign HS256, `EcdsaP256` keys sign ES256. This rules out `alg: none` and HS/ES confusion attacks.
- The `kid` header is `{keyId}:{version}`. Validation resolves that exact version, requires a signature and an expiry, and can be limited to certain keys with `AllowedKeyIds`.
- Time comes from `TimeProvider`, so token lifetimes are testable. `Validate` returns a failed result for bad tokens; it does not throw.

## Configuration

Section `Cipher`.

| Option | Default | Meaning |
|---|---|---|
| `PasswordHashIterations` | `210000` | PBKDF2-HMAC-SHA512 iterations for new password hashes (OWASP 2023 guidance) |
| `JwtClockSkew` | `00:01:00` | Clock skew tolerated when validating token lifetimes |

## Errors

`CipherException` is the base type. `CipherKeyNotFoundException`, `CipherKeyRevokedException` and `CipherDecryptionException` cover a missing key, a revoked key and a failed decryption.

## Design notes

- Only AES-256-GCM is offered, one vetted authenticated cipher instead of a menu of algorithms.
- Password hashing is PBKDF2 because Argon2 and scrypt are not in the .NET base library, and a foundation package should not take a native dependency. The hash format carries its own parameters, so the iteration count can grow later.
- RS256 is not supported. ES256 gives smaller tokens and there was no requirement for RSA.

## Depends on

Nothing else from this set of packages. Uses `Microsoft.IdentityModel.JsonWebTokens` for JWT handling.
