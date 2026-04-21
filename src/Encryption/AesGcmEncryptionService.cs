using System.Buffers.Binary;
using System.Security.Cryptography;
using Cipher.Keys;

namespace Cipher.Encryption;

internal sealed class AesGcmEncryptionService(IKeyStore keys) : IEncryptionService
{
    private const byte FormatV1 = 0x01;
    private const int NonceSize = 12, TagSize = 16, HeaderSize = 1 + 4;
    private const int MinLength = HeaderSize + NonceSize + TagSize;

    public async Task<byte[]> EncryptAsync(string keyId, ReadOnlyMemory<byte> plaintext, ReadOnlyMemory<byte> associatedData = default, CancellationToken cancellationToken = default)
    {
        var key = await keys.GetActiveAsync(keyId, cancellationToken).ConfigureAwait(false);
        RequireSymmetric(key);

        var envelope = new byte[MinLength + plaintext.Length];
        envelope[0] = FormatV1;
        BinaryPrimitives.WriteInt32BigEndian(envelope.AsSpan(1, 4), key.Version);
        var nonce = envelope.AsSpan(HeaderSize, NonceSize);
        var tag = envelope.AsSpan(HeaderSize + NonceSize, TagSize);
        var cipher = envelope.AsSpan(MinLength);
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(key.Material, TagSize);
        aes.Encrypt(nonce, plaintext.Span, cipher, tag, associatedData.Span);
        return envelope;
    }

    public async Task<byte[]> DecryptAsync(string keyId, ReadOnlyMemory<byte> envelope, ReadOnlyMemory<byte> associatedData = default, CancellationToken cancellationToken = default)
    {
        var version = GetKeyVersion(envelope.Span);
        var key = await keys.GetAsync(keyId, version, cancellationToken).ConfigureAwait(false);
        RequireSymmetric(key);

        var span = envelope.Span;
        var plaintext = new byte[span.Length - MinLength];
        try
        {
            using var aes = new AesGcm(key.Material, TagSize);
            aes.Decrypt(span.Slice(HeaderSize, NonceSize), span[MinLength..], span.Slice(HeaderSize + NonceSize, TagSize), plaintext, associatedData.Span);
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            throw new CipherDecryptionException("Decryption failed: data was tampered with, or the key/associated data does not match.", ex);
        }
    }

    public async Task<byte[]> ReEncryptAsync(string keyId, ReadOnlyMemory<byte> envelope, ReadOnlyMemory<byte> associatedData = default, CancellationToken cancellationToken = default)
    {
        var plaintext = await DecryptAsync(keyId, envelope, associatedData, cancellationToken).ConfigureAwait(false);
        try { return await EncryptAsync(keyId, plaintext, associatedData, cancellationToken).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public int GetKeyVersion(ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < MinLength || envelope[0] != FormatV1)
            throw new CipherDecryptionException("Not a valid Cipher envelope.");
        return BinaryPrimitives.ReadInt32BigEndian(envelope.Slice(1, 4));
    }

    private static void RequireSymmetric(CryptoKey key)
    {
        if (key.Kind != KeyKind.Symmetric)
            throw new CipherException($"Key '{key.Kid}' is {key.Kind}; encryption requires a Symmetric key.");
    }
}
