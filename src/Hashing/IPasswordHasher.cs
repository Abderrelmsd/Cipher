namespace Cipher.Hashing;

/// <summary>
/// Salted, deliberately slow password hashing (PBKDF2-HMAC-SHA512).
/// Stored format: <c>$qbx-pbkdf2-sha512$&lt;iterations&gt;$&lt;salt b64&gt;$&lt;hash b64&gt;</c> — self-describing, so iteration counts can be raised over time.
/// </summary>
public interface IPasswordHasher
{
    string Hash(string password);

    /// <summary>False for a wrong password or a malformed hash; never throws for bad input.</summary>
    bool Verify(string password, string storedHash);

    /// <summary>True when the stored hash was made with fewer iterations than currently configured (rehash after a successful login).</summary>
    bool NeedsRehash(string storedHash);
}
