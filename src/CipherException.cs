namespace Cipher;

/// <summary>Base type for all Cipher failures.</summary>
public class CipherException(string message, Exception? inner = null) : Exception(message, inner);

public sealed class CipherKeyNotFoundException(string keyId, int? version = null)
    : CipherException(version is null ? $"No key '{keyId}' exists." : $"Key '{keyId}' version {version} does not exist.");

public sealed class CipherKeyRevokedException(string keyId, int version)
    : CipherException($"Key '{keyId}' version {version} has been revoked.");

/// <summary>Authentication/decryption failed (tampered data, wrong key, wrong associated data).</summary>
public sealed class CipherDecryptionException(string message, Exception? inner = null) : CipherException(message, inner);
