using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Server.Auth.Data
{
    public class IdentityConfigSeed
    {
        public static async Task EnsureSeedData(IServiceProvider serviceProvider, IConfiguration config)
        {
            using (var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
                if (manager != null)
                {
                    await EnsureSeedApplicationsData(manager, config);
                }
            }
        }

        private static async Task EnsureSeedApplicationsData(IOpenIddictApplicationManager manager,
            IConfiguration config)
        {
            Console.WriteLine("Seeding database...");

            // API
            if (await manager.FindByClientIdAsync(config["Clients:ProductApi:ClientId"]) == null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = config["Clients:ProductApi:ClientId"],
                    ClientSecret = config["Clients:ProductApi:ClientSecret"],
                    Permissions =
                    {
                        Permissions.Endpoints.Introspection,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.ClientCredentials
                    },
                    DisplayName = config["Clients:ProductApi:Name"],
                };

                await manager.CreateAsync(descriptor);
            }

            if (await manager.FindByClientIdAsync(config["Clients:WebApp:ClientId"]) == null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = config["Clients:WebApp:ClientId"],
                    ClientSecret = config["Clients:WebApp:ClientSecret"],
                    RedirectUris =
                    {
                        new Uri(config["Clients:WebApp:RedirectUri"])
                    },
                    PostLogoutRedirectUris = 
                    {
                        new Uri(config["Clients:WebApp:PostLogoutRedirectUri"])
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Logout,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                        Permissions.Prefixes.Scope + config["Clients:ProductApi:ClientId"]
                    },
                    DisplayName = config["Clients:WebApp:Name"],
                });
            }

            Console.WriteLine("Database seeding completed...");
        }

    }
}
