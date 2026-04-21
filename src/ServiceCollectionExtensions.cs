using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Cipher.Encryption;
using Cipher.Hashing;
using Cipher.Jwt;
using Cipher.Keys;
using Cipher.Signing;

namespace Cipher;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers Cipher services. An <see cref="InMemoryKeyStore"/> is used unless an
    /// <see cref="IKeyStore"/> was registered beforehand (register yours first to override).
    /// </summary>
    public static IServiceCollection AddCipher(this IServiceCollection services, Action<CipherOptions>? configure = null)
    {
        var builder = services.AddOptions<CipherOptions>().ValidateDataAnnotations().ValidateOnStart();
        if (configure is not null) builder.Configure(configure);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IKeyStore, InMemoryKeyStore>();
        services.TryAddSingleton<IEncryptionService, AesGcmEncryptionService>();
        services.TryAddSingleton<IHashService, HashService>();
        services.TryAddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.TryAddSingleton<IHmacService, HmacService>();
        services.TryAddSingleton<IJwtService, JwtService>();
        return services;
    }
}
