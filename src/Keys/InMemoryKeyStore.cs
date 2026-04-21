using System.Security.Cryptography;

namespace Cipher.Keys;

/// <summary>Thread-safe in-process <see cref="IKeyStore"/>. Keys are lost on restart — use for tests, dev, or as a cache in front of a durable store.</summary>
public sealed class InMemoryKeyStore(TimeProvider? timeProvider = null) : IKeyStore
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, List<CryptoKey>> _keys = new(StringComparer.Ordinal);

    public Task<CryptoKey> GetActiveAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        lock (_gate)
        {
            if (_keys.TryGetValue(keyId, out var versions))
            {
                var active = versions.LastOrDefault(k => k.Status == KeyStatus.Active);
                if (active is not null) return Task.FromResult(active);
            }
        }
        throw new CipherKeyNotFoundException(keyId);
    }

    public Task<CryptoKey> GetAsync(string keyId, int version, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        lock (_gate)
        {
            var key = _keys.TryGetValue(keyId, out var versions) ? versions.FirstOrDefault(k => k.Version == version) : null;
            if (key is null) throw new CipherKeyNotFoundException(keyId, version);
            if (key.Status == KeyStatus.Revoked) throw new CipherKeyRevokedException(keyId, version);
            return Task.FromResult(key);
        }
    }

    public Task<CryptoKey> RotateAsync(string keyId, KeyKind kind = KeyKind.Symmetric, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        lock (_gate)
        {
            if (!_keys.TryGetValue(keyId, out var versions))
                _keys[keyId] = versions = [];

            for (var i = 0; i < versions.Count; i++)
                if (versions[i].Status == KeyStatus.Active)
                    versions[i] = versions[i] with { Status = KeyStatus.Retired };

            var next = new CryptoKey(keyId, versions.Count + 1, kind, Generate(kind), KeyStatus.Active, _time.GetUtcNow());
            versions.Add(next);
            return Task.FromResult(next);
        }
    }

    public Task RevokeAsync(string keyId, int version, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        lock (_gate)
        {
            if (!_keys.TryGetValue(keyId, out var versions)) throw new CipherKeyNotFoundException(keyId, version);
            var idx = versions.FindIndex(k => k.Version == version);
            if (idx < 0) throw new CipherKeyNotFoundException(keyId, version);
            versions[idx] = versions[idx] with { Status = KeyStatus.Revoked };
            return Task.CompletedTask;
        }
    }

    /// <summary>Generates fresh key material for <paramref name="kind"/>.</summary>
    public static byte[] Generate(KeyKind kind) => kind switch
    {
        KeyKind.Symmetric => RandomNumberGenerator.GetBytes(32),
        KeyKind.EcdsaP256 => ExportEcdsa(),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    private static byte[] ExportEcdsa()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa.ExportPkcs8PrivateKey();
    }
}
