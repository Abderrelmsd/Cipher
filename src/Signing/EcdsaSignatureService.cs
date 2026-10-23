using System.Security.Cryptography;
using Cipher.Keys;

namespace Cipher.Signing;

internal sealed class EcdsaSignatureService(IKeyStore keys) : IDigitalSignatureService
{
    public async Task<DigitalSignature> SignAsync(string keyId, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        var key = await keys.GetActiveAsync(keyId, cancellationToken).ConfigureAwait(false);
        using var ecdsa = Load(key);
        return new DigitalSignature(ecdsa.SignData(data.Span, HashAlgorithmName.SHA256), key.Version);
    }

    public async Task<bool> VerifyAsync(string keyId, int keyVersion, ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> signature, CancellationToken cancellationToken = default)
    {
        var key = await keys.GetAsync(keyId, keyVersion, cancellationToken).ConfigureAwait(false);
        using var ecdsa = Load(key);
        return ecdsa.VerifyData(data.Span, signature.Span, HashAlgorithmName.SHA256);
    }

    public async Task<string> ExportPublicKeyPemAsync(string keyId, int? keyVersion = null, CancellationToken cancellationToken = default)
    {
        var key = keyVersion is { } version
            ? await keys.GetAsync(keyId, version, cancellationToken).ConfigureAwait(false)
            : await keys.GetActiveAsync(keyId, cancellationToken).ConfigureAwait(false);
        using var ecdsa = Load(key);
        return ecdsa.ExportSubjectPublicKeyInfoPem();
    }

    public bool Verify(string publicKeyPem, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        using var ecdsa = FromPem(publicKeyPem);
        return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    public byte[] Sign(string privateKeyPem, ReadOnlySpan<byte> data)
    {
        using var ecdsa = FromPem(privateKeyPem);
        return ecdsa.SignData(data, HashAlgorithmName.SHA256);
    }

    public (string PrivateKeyPem, string PublicKeyPem) CreateKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (ecdsa.ExportPkcs8PrivateKeyPem(), ecdsa.ExportSubjectPublicKeyInfoPem());
    }

    private static ECDsa Load(CryptoKey key)
    {
        if (key.Kind != KeyKind.EcdsaP256)
            throw new CipherException($"Key '{key.Kid}' is {key.Kind}; ES256 signatures require an EcdsaP256 key.");
        var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(key.Material, out _);
        return ecdsa;
    }

    private static ECDsa FromPem(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);
        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(pem);
        }
        catch (ArgumentException ex)
        {
            ecdsa.Dispose();
            throw new CipherException("The PEM does not hold an ECDSA key: " + ex.Message);
        }

        if (ecdsa.KeySize != 256)
        {
            ecdsa.Dispose();
            throw new CipherException($"ES256 needs a P-256 key; this one has {ecdsa.KeySize} bits.");
        }

        return ecdsa;
    }
}
