using System.Security.Cryptography;
using System.Text;
using Cipher.Jwt;
using Cipher.Keys;
using Microsoft.Extensions.DependencyInjection;

namespace Cipher.Tests;

public class RsaKeyTests
{
    [Fact]
    public async Task Rsa_keys_give_a_pem_private_key_and_a_dkim_public_key_that_verify_each_other()
    {
        var store = new InMemoryKeyStore();
        var key = await store.RotateAsync("dkim/example", KeyKind.Rsa2048);
        Assert.Equal(KeyKind.Rsa2048, key.Kind);

        var pem = RsaKeys.PrivateKeyPem(key);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);

        using var signer = RSA.Create();
        signer.ImportFromPem(pem);
        Assert.Equal(2048, signer.KeySize);
        var data = Encoding.UTF8.GetBytes("header hash");
        var signature = signer.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using var verifier = RSA.Create();
        verifier.ImportSubjectPublicKeyInfo(Convert.FromBase64String(RsaKeys.PublicKeyBase64(key)), out _);
        Assert.True(verifier.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public async Task Rsa_keys_are_refused_for_tokens_and_other_kinds_are_refused_by_the_rsa_helpers()
    {
        var services = new ServiceCollection().AddCipher().BuildServiceProvider();
        var keys = services.GetRequiredService<IKeyStore>();
        await keys.RotateAsync("dkim", KeyKind.Rsa2048);
        var jwt = services.GetRequiredService<IJwtService>();
        await Assert.ThrowsAsync<CipherException>(() => jwt.CreateAsync("dkim", new JwtDescriptor { Issuer = "x", Subject = "y", Lifetime = TimeSpan.FromMinutes(1) }));

        var symmetric = await keys.RotateAsync("data");
        Assert.Throws<CipherException>(() => RsaKeys.PublicKeyBase64(symmetric));
    }
}
