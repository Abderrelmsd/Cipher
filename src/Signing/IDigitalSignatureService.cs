namespace Cipher.Signing;

/// <summary>
/// ES256 digital signatures (ECDSA P-256 over SHA-256, the 64-byte IEEE P1363 form JWS uses): signed by a named, versioned key in the key
/// store, verified by anyone holding its public key. For data others must check without a shared secret, such as a signed package.
/// </summary>
public interface IDigitalSignatureService
{
    /// <summary>Signs with the key's Active version (an <c>EcdsaP256</c> key).</summary>
    Task<DigitalSignature> SignAsync(string keyId, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);

    /// <summary>Verifies against a specific key version (retired versions still verify; revoked ones throw).</summary>
    Task<bool> VerifyAsync(string keyId, int keyVersion, ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> signature, CancellationToken cancellationToken = default);

    /// <summary>The public key of a version (the Active one when null) as PEM (SubjectPublicKeyInfo), to hand to whoever verifies.</summary>
    Task<string> ExportPublicKeyPemAsync(string keyId, int? keyVersion = null, CancellationToken cancellationToken = default);

    /// <summary>Stateless: verifies with a public key given as PEM (a trusted publisher's, say).</summary>
    bool Verify(string publicKeyPem, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    /// <summary>Stateless: signs with a private key given as PEM (PKCS#8 or SEC1), for tooling outside the key store.</summary>
    byte[] Sign(string privateKeyPem, ReadOnlySpan<byte> data);

    /// <summary>A new P-256 key pair as PEM: the private key (PKCS#8) and the public key (SubjectPublicKeyInfo).</summary>
    (string PrivateKeyPem, string PublicKeyPem) CreateKeyPair();
}

public sealed record DigitalSignature(byte[] Value, int KeyVersion, string Algorithm = DigitalSignature.Es256)
{
    public const string Es256 = "ES256";

    public string ToBase64() => Convert.ToBase64String(Value);
}
