using System.Security.Cryptography;
using System.Text;

namespace Cipher.Hashing;

internal sealed class HashService : IHashService
{
    public byte[] Hash(ReadOnlySpan<byte> data, HashAlgorithmKind algorithm = HashAlgorithmKind.Sha256) => algorithm switch
    {
        HashAlgorithmKind.Sha256 => SHA256.HashData(data),
        HashAlgorithmKind.Sha384 => SHA384.HashData(data),
        HashAlgorithmKind.Sha512 => SHA512.HashData(data),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    public string HashHex(string text, HashAlgorithmKind algorithm = HashAlgorithmKind.Sha256)
        => Convert.ToHexStringLower(Hash(Encoding.UTF8.GetBytes(text), algorithm));

    public async Task<byte[]> HashAsync(Stream stream, HashAlgorithmKind algorithm = HashAlgorithmKind.Sha256, CancellationToken cancellationToken = default) => algorithm switch
    {
        HashAlgorithmKind.Sha256 => await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false),
        HashAlgorithmKind.Sha384 => await SHA384.HashDataAsync(stream, cancellationToken).ConfigureAwait(false),
        HashAlgorithmKind.Sha512 => await SHA512.HashDataAsync(stream, cancellationToken).ConfigureAwait(false),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    public bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => CryptographicOperations.FixedTimeEquals(a, b);
}
