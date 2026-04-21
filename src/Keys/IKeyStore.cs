namespace Cipher.Keys;

/// <summary>
/// Versioned key storage and rotation. The in-memory implementation ships by default;
/// Keep (or any other vault) can supply a durable one.
/// </summary>
public interface IKeyStore
{
    /// <summary>The current Active version of <paramref name="keyId"/>.</summary>
    /// <exception cref="CipherKeyNotFoundException">No such key, or no active version.</exception>
    Task<CryptoKey> GetActiveAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>A specific version, for decrypt/verify of older data.</summary>
    /// <exception cref="CipherKeyNotFoundException"/>
    /// <exception cref="CipherKeyRevokedException">The version was revoked.</exception>
    Task<CryptoKey> GetAsync(string keyId, int version, CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a new version (creating version 1 if the key does not exist yet), makes it Active
    /// and retires the previous Active version.
    /// </summary>
    Task<CryptoKey> RotateAsync(string keyId, KeyKind kind = KeyKind.Symmetric, CancellationToken cancellationToken = default);

    /// <summary>Marks one version as Revoked. If it was the Active version, the key has no active version until rotated.</summary>
    Task RevokeAsync(string keyId, int version, CancellationToken cancellationToken = default);
}
