using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Cipher.Hashing;

internal sealed class Pbkdf2PasswordHasher(IOptions<CipherOptions> options) : IPasswordHasher
{
    private const string Prefix = "$qbx-pbkdf2-sha512$";
    private const int SaltSize = 16, HashSize = 64;

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        var iterations = options.Value.PasswordHashIterations;
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Derive(password, salt, iterations);
        return $"{Prefix}{iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool Verify(string password, string storedHash)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (!TryParse(storedHash, out var iterations, out var salt, out var expected)) return false;
        var actual = Derive(password, salt, iterations);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public bool NeedsRehash(string storedHash)
        => !TryParse(storedHash, out var iterations, out _, out _) || iterations < options.Value.PasswordHashIterations;

    private static byte[] Derive(string password, byte[] salt, int iterations)
        => Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA512, HashSize);

    private static bool TryParse(string? stored, out int iterations, out byte[] salt, out byte[] hash)
    {
        iterations = 0; salt = []; hash = [];
        if (stored is null || !stored.StartsWith(Prefix, StringComparison.Ordinal)) return false;
        var parts = stored[Prefix.Length..].Split('$');
        if (parts.Length != 3 || !int.TryParse(parts[0], out iterations) || iterations < 1) return false;
        try { salt = Convert.FromBase64String(parts[1]); hash = Convert.FromBase64String(parts[2]); }
        catch (FormatException) { return false; }
        return salt.Length > 0 && hash.Length == HashSize;
    }
}
