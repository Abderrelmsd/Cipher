using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Cipher.Keys;

namespace Cipher.Jwt;

internal sealed class JwtService(IKeyStore keys, IOptions<CipherOptions> options, TimeProvider timeProvider) : IJwtService
{
    private readonly JsonWebTokenHandler _handler = new();

    public async Task<string> CreateAsync(string keyId, JwtDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        var key = await keys.GetActiveAsync(keyId, cancellationToken).ConfigureAwait(false);
        var now = timeProvider.GetUtcNow().UtcDateTime;

        var claims = new Dictionary<string, object>(descriptor.Claims ?? new Dictionary<string, object>());
        if (descriptor.Subject is not null) claims[JwtRegisteredClaimNames.Sub] = descriptor.Subject;
        claims[JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N");

        using var ecdsa = key.Kind == KeyKind.EcdsaP256 ? ImportEcdsa(key) : null;
        var (securityKey, alg) = ToSigningKey(key, ecdsa);

        var token = new SecurityTokenDescriptor
        {
            Issuer = descriptor.Issuer,
            Audience = descriptor.Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = now + descriptor.Lifetime,
            Claims = claims,
            SigningCredentials = new SigningCredentials(securityKey, alg) { CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false } },
        };
        return _handler.CreateToken(token);
    }

    public async Task<JwtValidationResult> ValidateAsync(string token, JwtValidationOptions? validation = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token)) return JwtValidationResult.Fail("Token is empty.");
        if (!_handler.CanReadToken(token)) return JwtValidationResult.Fail("Token is malformed.");

        JsonWebToken parsed;
        try { parsed = _handler.ReadJsonWebToken(token); }
        catch (Exception ex) when (ex is ArgumentException or SecurityTokenException) { return JwtValidationResult.Fail("Token is malformed."); }

        if (!TryParseKid(parsed.Kid, out var keyId, out var version))
            return JwtValidationResult.Fail("Token has no usable 'kid'.");
        if (validation?.AllowedKeyIds is { Count: > 0 } allowed && !allowed.Contains(keyId))
            return JwtValidationResult.Fail("Signing key is not allowed.");

        CryptoKey key;
        try { key = await keys.GetAsync(keyId, version, cancellationToken).ConfigureAwait(false); }
        catch (CipherException ex) { return JwtValidationResult.Fail(ex.Message); }

        using var ecdsa = key.Kind == KeyKind.EcdsaP256 ? ImportEcdsa(key) : null;
        var (securityKey, alg) = ToSigningKey(key, ecdsa);

        var parameters = new TokenValidationParameters
        {
            IssuerSigningKey = securityKey,
            ValidAlgorithms = [alg],
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = options.Value.JwtClockSkew,
            LifetimeValidator = (nbf, exp, _, p) =>
            {
                var now = timeProvider.GetUtcNow().UtcDateTime;
                return exp is not null && now <= exp.Value.Add(p.ClockSkew) && (nbf is null || now >= nbf.Value.Subtract(p.ClockSkew));
            },
            ValidateIssuer = validation?.ValidIssuer is not null,
            ValidIssuer = validation?.ValidIssuer,
            ValidateAudience = validation?.ValidAudience is not null,
            ValidAudience = validation?.ValidAudience,
        };

        var result = await _handler.ValidateTokenAsync(token, parameters).ConfigureAwait(false);
        if (!result.IsValid) return JwtValidationResult.Fail(result.Exception?.Message ?? "Token is invalid.");
        return new JwtValidationResult(true, new Dictionary<string, object>(result.Claims), null);
    }

    private static (SecurityKey Key, string Algorithm) ToSigningKey(CryptoKey key, ECDsa? ecdsa) => key.Kind switch
    {
        KeyKind.Symmetric => (new SymmetricSecurityKey(key.Material) { KeyId = key.Kid }, SecurityAlgorithms.HmacSha256),
        KeyKind.EcdsaP256 => (new ECDsaSecurityKey(ecdsa!) { KeyId = key.Kid }, SecurityAlgorithms.EcdsaSha256),
        _ => throw new CipherException($"Unsupported key kind {key.Kind}."),
    };

    private static ECDsa ImportEcdsa(CryptoKey key)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(key.Material, out _);
        return ecdsa;
    }

    private static bool TryParseKid(string? kid, out string keyId, out int version)
    {
        keyId = ""; version = 0;
        var i = kid?.LastIndexOf(':') ?? -1;
        if (i <= 0 || !int.TryParse(kid![(i + 1)..], out version)) return false;
        keyId = kid[..i];
        return true;
    }
}
