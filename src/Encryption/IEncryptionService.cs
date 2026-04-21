namespace Cipher.Encryption;

/// <summary>
/// AES-256-GCM authenticated encryption keyed by a named, versioned key.
/// Envelope layout: <c>[0x01 format][int32 BE key version][12-byte nonce][16-byte tag][ciphertext]</c>,
/// so decryption always finds the right key version and rotation never strands old data.
/// </summary>
public interface IEncryptionService
{
    Task<byte[]> EncryptAsync(string keyId, ReadOnlyMemory<byte> plaintext, ReadOnlyMemory<byte> associatedData = default, CancellationToken cancellationToken = default);

    /// <exception cref="CipherDecryptionException">Tampered data, wrong key, or mismatched associated data.</exception>
    Task<byte[]> DecryptAsync(string keyId, ReadOnlyMemory<byte> envelope, ReadOnlyMemory<byte> associatedData = default, CancellationToken cancellationToken = default);

    /// <summary>Decrypts under whatever version the envelope names and re-encrypts under the key's current Active version.</summary>
    Task<byte[]> ReEncryptAsync(string keyId, ReadOnlyMemory<byte> envelope, ReadOnlyMemory<byte> associatedData = default, CancellationToken cancellationToken = default);

    /// <summary>Reads the key version from an envelope without decrypting (for lazy re-encryption sweeps).</summary>
    int GetKeyVersion(ReadOnlySpan<byte> envelope);
}
