using Microsoft.Extensions.DependencyInjection;

namespace MarkoPapic.TwoFactorAuthentication
{
    /// <summary>
    /// Extension methods for .NET Core middleware.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers <c>TwoFactorAuthenticationManager</c> as a service, making it available via .NET dependency injection.
        /// </summary>
        /// <param name="services">The <c>Microsoft.Extensions.DependencyInjection.IServiceCollection</c> to add services to.</param>
        /// <returns>A <c>Microsoft.Extensions.DependencyInjection.IServiceCollection</c> that can be used to further configure the services.</returns>
        public static IServiceCollection AddTwoFactorAuthentication(this IServiceCollection services) => services.AddTransient<TwoFactorAuthenticationManager>();
    }
}
