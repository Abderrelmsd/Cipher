using Microsoft.Extensions.DependencyInjection;
using Cipher.Hashing;

namespace Cipher.Tests;

public class HashingTests
{
    private readonly ServiceProvider _sp = TestHost.Build();

    [Fact]
    public void Sha256_matches_known_vector()
        => Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", _sp.GetRequiredService<IHashService>().HashHex("abc"));

    [Fact]
    public async Task Stream_hash_equals_buffer_hash()
    {
        var h = _sp.GetRequiredService<IHashService>();
        var data = new byte[100_000]; new Random(1).NextBytes(data);
        Assert.Equal(h.Hash(data, HashAlgorithmKind.Sha512), await h.HashAsync(new MemoryStream(data), HashAlgorithmKind.Sha512));
    }

    [Fact]
    public void Password_roundtrip_and_salting()
    {
        var p = _sp.GetRequiredService<IPasswordHasher>();
        var a = p.Hash("correct horse");
        Assert.True(p.Verify("correct horse", a));
        Assert.False(p.Verify("wrong", a));
        Assert.NotEqual(a, p.Hash("correct horse"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("plain")]
    [InlineData("$qbx-pbkdf2-sha512$abc$x$y")]
    [InlineData("$qbx-pbkdf2-sha512$10000$!!!$???")]
    public void Malformed_hashes_verify_false_without_throwing(string stored)
        => Assert.False(_sp.GetRequiredService<IPasswordHasher>().Verify("x", stored));

    [Fact]
    public void NeedsRehash_when_iterations_increase()
    {
        var oldHash = _sp.GetRequiredService<IPasswordHasher>().Hash("pw");
        using var stronger = TestHost.Build(o => o.PasswordHashIterations = 20_000);
        var p = stronger.GetRequiredService<IPasswordHasher>();
        Assert.True(p.NeedsRehash(oldHash));
        Assert.True(p.Verify("pw", oldHash)); // old hashes keep verifying
        Assert.False(p.NeedsRehash(p.Hash("pw")));
    }
}
