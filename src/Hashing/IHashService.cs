namespace Cipher.Hashing;

public enum HashAlgorithmKind { Sha256, Sha384, Sha512 }

/// <summary>General-purpose (non-password) hashing.</summary>
public interface IHashService
{
    byte[] Hash(ReadOnlySpan<byte> data, HashAlgorithmKind algorithm = HashAlgorithmKind.Sha256);

    /// <summary>Lower-case hex digest of UTF-8 <paramref name="text"/>.</summary>
    string HashHex(string text, HashAlgorithmKind algorithm = HashAlgorithmKind.Sha256);

    Task<byte[]> HashAsync(Stream stream, HashAlgorithmKind algorithm = HashAlgorithmKind.Sha256, CancellationToken cancellationToken = default);

    /// <summary>Constant-time comparison.</summary>
    bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b);
}
