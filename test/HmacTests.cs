using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Cipher.Keys;
using Cipher.Signing;

namespace Cipher.Tests;

public class HmacTests
{
    private readonly ServiceProvider _sp = TestHost.Build();
    private IHmacService Hmac => _sp.GetRequiredService<IHmacService>();

    [Fact]
    public void Matches_rfc4231_test_case_2()
    {
        var sig = Hmac.Sign(Encoding.ASCII.GetBytes("Jefe"), Encoding.ASCII.GetBytes("what do ya want for nothing?"));
        Assert.Equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", Convert.ToHexStringLower(sig));
    }

    [Fact]
    public async Task Sign_and_verify_with_key_versions()
    {
        await _sp.GetRequiredService<IKeyStore>().RotateAsync("hook");
        var data = "payload"u8.ToArray();
        var sig = await Hmac.SignAsync("hook", data);

        Assert.True(await Hmac.VerifyAsync("hook", sig.KeyVersion, data, sig.Value));
        Assert.False(await Hmac.VerifyAsync("hook", sig.KeyVersion, "other"u8.ToArray(), sig.Value));

        await _sp.GetRequiredService<IKeyStore>().RotateAsync("hook"); // v1 retired but still verifies
        Assert.True(await Hmac.VerifyAsync("hook", 1, data, sig.Value));
    }

    [Fact]
    public void Stateless_verify_rejects_wrong_secret_and_truncated_signature()
    {
        var sig = Hmac.Sign("s1"u8, "d"u8);
        Assert.True(Hmac.Verify("s1"u8, "d"u8, sig));
        Assert.False(Hmac.Verify("s2"u8, "d"u8, sig));
        Assert.False(Hmac.Verify("s1"u8, "d"u8, sig.AsSpan(0, 16)));
    }
}
