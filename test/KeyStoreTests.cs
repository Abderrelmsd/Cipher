using Cipher.Keys;

namespace Cipher.Tests;

public class KeyStoreTests
{
    private readonly InMemoryKeyStore _store = new();

    [Fact]
    public async Task Rotate_creates_version_1_then_retires_previous()
    {
        var v1 = await _store.RotateAsync("k");
        var v2 = await _store.RotateAsync("k");

        Assert.Equal(1, v1.Version);
        Assert.Equal(2, v2.Version);
        Assert.Equal(2, (await _store.GetActiveAsync("k")).Version);
        Assert.Equal(KeyStatus.Retired, (await _store.GetAsync("k", 1)).Status);
        Assert.NotEqual(v1.Material, v2.Material);
    }

    [Fact]
    public async Task Missing_key_throws()
    {
        await Assert.ThrowsAsync<CipherKeyNotFoundException>(() => _store.GetActiveAsync("nope"));
        await _store.RotateAsync("k");
        await Assert.ThrowsAsync<CipherKeyNotFoundException>(() => _store.GetAsync("k", 9));
    }

    [Fact]
    public async Task Revoked_version_cannot_be_fetched_and_active_is_lost()
    {
        var v1 = await _store.RotateAsync("k");
        await _store.RevokeAsync("k", v1.Version);

        await Assert.ThrowsAsync<CipherKeyRevokedException>(() => _store.GetAsync("k", 1));
        await Assert.ThrowsAsync<CipherKeyNotFoundException>(() => _store.GetActiveAsync("k"));
    }

    [Fact]
    public async Task Ecdsa_keys_are_generated_and_symmetric_keys_are_32_bytes()
    {
        Assert.Equal(32, (await _store.RotateAsync("s")).Material.Length);
        Assert.True((await _store.RotateAsync("e", KeyKind.EcdsaP256)).Material.Length > 32);
    }

    [Fact]
    public async Task ToString_does_not_leak_material()
    {
        var k = await _store.RotateAsync("k");
        Assert.DoesNotContain(Convert.ToBase64String(k.Material), k.ToString());
    }
}
