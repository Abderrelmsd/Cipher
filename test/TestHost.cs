using Microsoft.Extensions.DependencyInjection;

namespace Cipher.Tests;

internal static class TestHost
{
    public static ServiceProvider Build(Action<CipherOptions>? configure = null, Action<IServiceCollection>? pre = null)
    {
        var services = new ServiceCollection();
        pre?.Invoke(services);
        services.AddCipher(o => { o.PasswordHashIterations = 10_000; configure?.Invoke(o); });
        return services.BuildServiceProvider();
    }
}
