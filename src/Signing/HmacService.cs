using System.Security.Cryptography;
using Cipher.Keys;

namespace Cipher.Signing;

internal sealed class HmacService(IKeyStore keys) : IHmacService
{
    public async Task<HmacSignature> SignAsync(string keyId, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        var key = await keys.GetActiveAsync(keyId, cancellationToken).ConfigureAwait(false);
        RequireSymmetric(key);
        return new HmacSignature(Sign(key.Material, data.Span), key.Version);
    }

    public async Task<bool> VerifyAsync(string keyId, int keyVersion, ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> signature, CancellationToken cancellationToken = default)
    {
        var key = await keys.GetAsync(keyId, keyVersion, cancellationToken).ConfigureAwait(false);
        RequireSymmetric(key);
        return Verify(key.Material, data.Span, signature.Span);
    }

    public byte[] Sign(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> data) => HMACSHA256.HashData(secret, data);

    public bool Verify(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        => CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(secret, data), signature);

    private static void RequireSymmetric(CryptoKey key)
    {
        if (key.Kind != KeyKind.Symmetric)
            throw new CipherException($"Key '{key.Kid}' is {key.Kind}; HMAC requires a Symmetric key.");
    }
}
