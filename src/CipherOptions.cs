using System.ComponentModel.DataAnnotations;

namespace Cipher;

public sealed class CipherOptions
{
    public const string SectionName = "Cipher";

    /// <summary>PBKDF2-HMAC-SHA512 iterations for new password hashes (OWASP 2023: 210,000 for SHA-512).</summary>
    [Range(10_000, 10_000_000)]
    public int PasswordHashIterations { get; set; } = 210_000;

    /// <summary>Allowed clock skew when validating JWT lifetimes.</summary>
    public TimeSpan JwtClockSkew { get; set; } = TimeSpan.FromMinutes(1);
}
