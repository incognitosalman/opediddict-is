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
            if (await manager.FindByClientIdAsync(config["Clients:WebApp:ClientId"]) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = config["Clients:WebApp:ClientId"],
                    ClientSecret = config["Clients:WebApp:ClientSecret"],
                    RedirectUris =
                    {
                        new Uri(config["Clients:WebApp:Url"])
                    },
                    PostLogoutRedirectUris = 
                    {
                        new Uri(config["Clients:WebApp:PostLogoutRedirectUris"])
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                        Permissions.Prefixes.Scope + config["Clients:ProductApi:ClientId"],
                        Permissions.Prefixes.Scope + config["Clients:UserApi:ClientId"]
                    },
                    DisplayName = config["Clients:WebApp:Name"],
                });
            }
        }

    }
}
