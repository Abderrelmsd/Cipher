using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Cipher.Keys;
using Cipher.Signing;

namespace Cipher.Tests;

public class DigitalSignatureTests
{
    private readonly ServiceProvider _sp = TestHost.Build();
    private IDigitalSignatureService Signatures => _sp.GetRequiredService<IDigitalSignatureService>();
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_key_in_the_store_signs_and_its_exported_public_key_verifies()
    {
        await _sp.GetRequiredService<IKeyStore>().RotateAsync("packs", KeyKind.EcdsaP256, Ct);
        var data = "manifest"u8.ToArray();
        var signature = await Signatures.SignAsync("packs", data, Ct);

        Assert.Equal(64, signature.Value.Length); // IEEE P1363, as JWS ES256
        Assert.Equal("ES256", signature.Algorithm);
        Assert.True(await Signatures.VerifyAsync("packs", signature.KeyVersion, data, signature.Value, Ct));
        Assert.False(await Signatures.VerifyAsync("packs", signature.KeyVersion, "other"u8.ToArray(), signature.Value, Ct));

        var publicPem = await Signatures.ExportPublicKeyPemAsync("packs", cancellationToken: Ct);
        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", publicPem);
        Assert.True(Signatures.Verify(publicPem, data, signature.Value));
        Assert.DoesNotContain("PRIVATE", publicPem);

        await _sp.GetRequiredService<IKeyStore>().RotateAsync("packs", KeyKind.EcdsaP256, Ct); // the old version still verifies
        Assert.True(await Signatures.VerifyAsync("packs", signature.KeyVersion, data, signature.Value, Ct));
    }

    [Fact]
    public void Stateless_signing_interoperates_with_plain_ecdsa()
    {
        var (privatePem, publicPem) = Signatures.CreateKeyPair();
        var data = "pack"u8.ToArray();

        // Signed by Cipher, verified by plain .NET ECDSA (what a pack consumer without Cipher does), and the other way round.
        using var other = ECDsa.Create();
        other.ImportFromPem(publicPem);
        Assert.True(other.VerifyData(data, Signatures.Sign(privatePem, data), HashAlgorithmName.SHA256));

        using var publisher = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.True(Signatures.Verify(publisher.ExportSubjectPublicKeyInfoPem(), data, publisher.SignData(data, HashAlgorithmName.SHA256)));
        Assert.False(Signatures.Verify(publicPem, data, publisher.SignData(data, HashAlgorithmName.SHA256)));
    }

    [Fact]
    public async Task Wrong_keys_are_refused_clearly()
    {
        await _sp.GetRequiredService<IKeyStore>().RotateAsync("secret", KeyKind.Symmetric, Ct);
        await Assert.ThrowsAsync<CipherException>(() => Signatures.SignAsync("secret", new byte[] { 1 }, Ct));
        Assert.Throws<CipherException>(() => Signatures.Verify("not a pem", [1], [1]));

        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<CipherException>(() => Signatures.Verify(p384.ExportSubjectPublicKeyInfoPem(), [1], [1]));
    }
}
