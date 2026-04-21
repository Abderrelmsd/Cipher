namespace Cipher.Jwt;

/// <summary>
/// Signs and validates JWTs with keys from <see cref="Keys.IKeyStore"/>.
/// Symmetric keys sign HS256; EcdsaP256 keys sign ES256. The algorithm is dictated by the stored key,
/// never by the token header, which rules out algorithm-confusion attacks. The <c>kid</c> header is <c>{keyId}:{version}</c>.
/// </summary>
public interface IJwtService
{
    Task<string> CreateAsync(string keyId, JwtDescriptor descriptor, CancellationToken cancellationToken = default);

    Task<JwtValidationResult> ValidateAsync(string token, JwtValidationOptions? options = null, CancellationToken cancellationToken = default);
}

public sealed class JwtDescriptor
{
    public string? Issuer { get; init; }
    public string? Audience { get; init; }
    public string? Subject { get; init; }
    public required TimeSpan Lifetime { get; init; }
    public IReadOnlyDictionary<string, object>? Claims { get; init; }
}

public sealed class JwtValidationOptions
{
    public string? ValidIssuer { get; init; }
    public string? ValidAudience { get; init; }

    /// <summary>Restricts which key names may have signed the token. Null/empty allows any key in the store.</summary>
    public IReadOnlyCollection<string>? AllowedKeyIds { get; init; }
}

public sealed record JwtValidationResult(bool IsValid, IReadOnlyDictionary<string, object> Claims, string? Error)
{
    public static JwtValidationResult Fail(string error) => new(false, new Dictionary<string, object>(), error);
}
