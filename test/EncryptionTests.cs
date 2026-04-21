using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Cipher.Encryption;
using Cipher.Keys;

namespace Cipher.Tests;

public class EncryptionTests
{
    private readonly ServiceProvider _sp = TestHost.Build();
    private IEncryptionService Enc => _sp.GetRequiredService<IEncryptionService>();
    private IKeyStore Keys => _sp.GetRequiredService<IKeyStore>();

    public EncryptionTests() => Keys.RotateAsync("data").GetAwaiter().GetResult();

    [Fact]
    public async Task Roundtrip()
    {
        var env = await Enc.EncryptAsync("data", "hello"u8.ToArray());
        Assert.Equal("hello", Encoding.UTF8.GetString(await Enc.DecryptAsync("data", env)));
    }

    [Fact]
    public async Task Same_plaintext_yields_different_envelopes()
    {
        var a = await Enc.EncryptAsync("data", "x"u8.ToArray());
        var b = await Enc.EncryptAsync("data", "x"u8.ToArray());
        Assert.NotEqual(a, b);
    }

    [Fact]
    public async Task Tampering_is_detected()
    {
        var env = await Enc.EncryptAsync("data", "secret"u8.ToArray());
        env[^1] ^= 0x01;
        await Assert.ThrowsAsync<CipherDecryptionException>(() => Enc.DecryptAsync("data", env));
    }

    [Fact]
    public async Task Associated_data_must_match()
    {
        var env = await Enc.EncryptAsync("data", "secret"u8.ToArray(), "tenant-1"u8.ToArray());
        Assert.Equal("secret"u8.ToArray(), await Enc.DecryptAsync("data", env, "tenant-1"u8.ToArray()));
        await Assert.ThrowsAsync<CipherDecryptionException>(() => Enc.DecryptAsync("data", env, "tenant-2"u8.ToArray()));
    }

    [Fact]
    public async Task Old_versions_still_decrypt_after_rotation_and_reencrypt_upgrades_them()
    {
        var old = await Enc.EncryptAsync("data", "payload"u8.ToArray());
        await Keys.RotateAsync("data");

        Assert.Equal(1, Enc.GetKeyVersion(old));
        Assert.Equal("payload"u8.ToArray(), await Enc.DecryptAsync("data", old));

        var upgraded = await Enc.ReEncryptAsync("data", old);
        Assert.Equal(2, Enc.GetKeyVersion(upgraded));
        Assert.Equal("payload"u8.ToArray(), await Enc.DecryptAsync("data", upgraded));
    }

    [Fact]
    public async Task Revoked_version_cannot_decrypt()
    {
        var env = await Enc.EncryptAsync("data", "x"u8.ToArray());
        await Keys.RevokeAsync("data", 1);
        await Assert.ThrowsAsync<CipherKeyRevokedException>(() => Enc.DecryptAsync("data", env));
    }

    [Fact]
    public async Task Garbage_envelope_is_rejected()
    {
        await Assert.ThrowsAsync<CipherDecryptionException>(() => Enc.DecryptAsync("data", new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public async Task Empty_plaintext_works()
    {
        var env = await Enc.EncryptAsync("data", ReadOnlyMemory<byte>.Empty);
        Assert.Empty(await Enc.DecryptAsync("data", env));
    }

    [Fact]
    public async Task Asymmetric_key_is_rejected_for_encryption()
    {
        await Keys.RotateAsync("ec", KeyKind.EcdsaP256);
        await Assert.ThrowsAsync<CipherException>(() => Enc.EncryptAsync("ec", "x"u8.ToArray()));
    }
}
