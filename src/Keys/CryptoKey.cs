namespace Cipher.Keys;

public enum KeyKind
{
    /// <summary>32-byte random secret: AES-256-GCM, HMAC-SHA256/512, HS256 JWTs.</summary>
    Symmetric = 0,

    /// <summary>ECDSA P-256 key pair stored as PKCS#8 private key: ES256 JWTs.</summary>
    EcdsaP256 = 1,
}

public enum KeyStatus
{
    /// <summary>Current version: used for new encrypt/sign operations and still valid for decrypt/verify.</summary>
    Active = 0,

    /// <summary>Superseded by a newer version: decrypt/verify only.</summary>
    Retired = 1,

    /// <summary>Compromised or withdrawn: never usable.</summary>
    Revoked = 2,
}

/// <summary>One immutable version of a named key.</summary>
public sealed record CryptoKey(
    string KeyId,
    int Version,
    KeyKind Kind,
    byte[] Material,
    KeyStatus Status,
    DateTimeOffset CreatedAt)
{
    /// <summary>Stable identifier embedded in tokens and envelopes: <c>{KeyId}:{Version}</c>.</summary>
    public string Kid => $"{KeyId}:{Version}";

    public override string ToString() => $"CryptoKey({Kid}, {Kind}, {Status})"; // never print material
}
