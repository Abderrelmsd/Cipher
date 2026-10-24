using System.Security.Cryptography;

namespace Cipher.Keys;

/// <summary>Helpers for <see cref="KeyKind.Rsa2048"/> keys: the forms DKIM needs.</summary>
public static class RsaKeys
{
    /// <summary>The private key as PKCS#8 PEM (<c>-----BEGIN PRIVATE KEY-----</c>), as an MTA's DKIM signer expects it.</summary>
    public static string PrivateKeyPem(CryptoKey key)
    {
        Require(key);
        return PemEncoding.WriteString("PRIVATE KEY", key.Material);
    }

    /// <summary>The public key as base64 SubjectPublicKeyInfo: the <c>p=</c> value of a DKIM DNS record.</summary>
    public static string PublicKeyBase64(CryptoKey key)
    {
        Require(key);
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(key.Material, out _);
        return Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
    }

    private static void Require(CryptoKey key)
    {
        if (key.Kind != KeyKind.Rsa2048) throw new CipherException($"Key '{key.Kid}' is not an RSA key.");
    }
}
