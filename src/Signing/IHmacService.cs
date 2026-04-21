namespace Cipher.Signing;

/// <summary>HMAC-SHA256 signing/verification with named, versioned keys. Verification is constant-time.</summary>
public interface IHmacService
{
    /// <summary>Signs with the key's Active version; returns the signature and the version used.</summary>
    Task<HmacSignature> SignAsync(string keyId, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);

    /// <summary>Verifies against a specific key version (retired versions still verify; revoked ones throw).</summary>
    Task<bool> VerifyAsync(string keyId, int keyVersion, ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> signature, CancellationToken cancellationToken = default);

    /// <summary>Stateless variant for secrets the caller manages (e.g. a webhook signing secret fetched from Keep).</summary>
    byte[] Sign(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> data);

    bool Verify(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
}

public sealed record HmacSignature(byte[] Value, int KeyVersion)
{
    public string ToHex() => Convert.ToHexStringLower(Value);
}
