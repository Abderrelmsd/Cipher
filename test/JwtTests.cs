using Microsoft.Extensions.DependencyInjection;
using Cipher.Jwt;
using Cipher.Keys;

namespace Cipher.Tests;

public class JwtTests
{
    private sealed class FakeTime(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private readonly FakeTime _time = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
    private readonly ServiceProvider _sp;
    private IJwtService Jwt => _sp.GetRequiredService<IJwtService>();
    private IKeyStore Keys => _sp.GetRequiredService<IKeyStore>();

    public JwtTests() => _sp = TestHost.Build(pre: s => s.AddSingleton<TimeProvider>(_time));

    private static string Kid(string token)
    {
        var h = token.Split('.')[0].Replace('-', '+').Replace('_', '/');
        h = h.PadRight(h.Length + (4 - h.Length % 4) % 4, '=');
        return System.Text.Json.JsonDocument.Parse(Convert.FromBase64String(h)).RootElement.GetProperty("kid").GetString()!;
    }

    private static JwtDescriptor Descriptor(TimeSpan? life = null) => new()
    {
        Issuer = "issuer", Audience = "app", Subject = "user-1", Lifetime = life ?? TimeSpan.FromMinutes(5),
        Claims = new Dictionary<string, object> { ["tenant"] = "t1", ["perms"] = new[] { "a", "b" } },
    };

    [Theory]
    [InlineData(KeyKind.Symmetric)]
    [InlineData(KeyKind.EcdsaP256)]
    public async Task Create_and_validate(KeyKind kind)
    {
        await Keys.RotateAsync("sess", kind);
        var token = await Jwt.CreateAsync("sess", Descriptor());
        var r = await Jwt.ValidateAsync(token, new JwtValidationOptions { ValidIssuer = "issuer", ValidAudience = "app" });

        Assert.True(r.IsValid, r.Error);
        Assert.Equal("user-1", r.Claims["sub"]);
        Assert.Equal("t1", r.Claims["tenant"]);
    }

    [Fact]
    public async Task Expired_token_is_rejected_after_skew()
    {
        await Keys.RotateAsync("sess");
        var token = await Jwt.CreateAsync("sess", Descriptor(TimeSpan.FromMinutes(5)));

        _time.Now += TimeSpan.FromMinutes(5.5);
        Assert.True((await Jwt.ValidateAsync(token)).IsValid); // within 1 min skew
        _time.Now += TimeSpan.FromMinutes(1);
        Assert.False((await Jwt.ValidateAsync(token)).IsValid);
    }

    [Fact]
    public async Task Tampered_payload_is_rejected()
    {
        await Keys.RotateAsync("sess");
        var parts = (await Jwt.CreateAsync("sess", Descriptor())).Split('.');
        var forged = $"{parts[0]}.{Convert.ToBase64String("{\"sub\":\"admin\"}"u8.ToArray()).TrimEnd('=')}.{parts[2]}";
        Assert.False((await Jwt.ValidateAsync(forged)).IsValid);
    }

    [Fact]
    public async Task Wrong_issuer_or_audience_is_rejected()
    {
        await Keys.RotateAsync("sess");
        var token = await Jwt.CreateAsync("sess", Descriptor());
        Assert.False((await Jwt.ValidateAsync(token, new JwtValidationOptions { ValidIssuer = "evil" })).IsValid);
        Assert.False((await Jwt.ValidateAsync(token, new JwtValidationOptions { ValidAudience = "other" })).IsValid);
    }

    [Fact]
    public async Task Rotation_keeps_old_tokens_valid_until_revoked()
    {
        await Keys.RotateAsync("sess");
        var token = await Jwt.CreateAsync("sess", Descriptor());
        await Keys.RotateAsync("sess");

        Assert.True((await Jwt.ValidateAsync(token)).IsValid);
        Assert.Equal("sess:2", Kid(await Jwt.CreateAsync("sess", Descriptor())));

        await Keys.RevokeAsync("sess", 1);
        Assert.False((await Jwt.ValidateAsync(token)).IsValid);
    }

    [Fact]
    public async Task Key_allow_list_is_enforced()
    {
        await Keys.RotateAsync("sess");
        await Keys.RotateAsync("other");
        var token = await Jwt.CreateAsync("other", Descriptor());
        Assert.False((await Jwt.ValidateAsync(token, new JwtValidationOptions { AllowedKeyIds = ["sess"] })).IsValid);
    }

    [Fact]
    public async Task Alg_none_and_garbage_are_rejected()
    {
        var none = "eyJhbGciOiJub25lIiwia2lkIjoic2VzczoxIn0.eyJzdWIiOiJ4In0.";
        Assert.False((await Jwt.ValidateAsync(none)).IsValid);
        Assert.False((await Jwt.ValidateAsync("not-a-jwt")).IsValid);
        Assert.False((await Jwt.ValidateAsync("")).IsValid);
    }
}
