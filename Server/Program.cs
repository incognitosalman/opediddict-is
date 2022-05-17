using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Server.Auth.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ServerDbContext>(options =>
{
    // Configure the context to use an SQL Server
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));

    // Register the entity sets needed by OpenIddict.
    options.UseOpenIddict();
});

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ServerDbContext>()
    .AddDefaultTokenProviders()
    .AddDefaultUI();

builder.Services.Configure<IdentityOptions>(options =>
{
                // Configure Identity to use the same JWT claims as OpenIddict instead
                // of the legacy WS-Federation claims it uses by default (ClaimTypes),
                // which saves you from doing the mapping in your authorization controller.
    options.ClaimsIdentity.UserNameClaimType = Claims.Name;
    options.ClaimsIdentity.UserIdClaimType = Claims.Subject;
    options.ClaimsIdentity.RoleClaimType = Claims.Role;
    options.ClaimsIdentity.EmailClaimType = Claims.Email;

                // Note: to require account confirmation before login,
                // register an email sender service (IEmailSender) and
                // set options.SignIn.RequireConfirmedAccount to true.
                //
                // For more information, visit https://aka.ms/aspaccountconf.
    options.SignIn.RequireConfirmedAccount = false;

                // Password settings.
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 4;
    options.Password.RequiredUniqueChars = 0;

                // Lockout settings.
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

                // User settings.
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;
});

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        // Configure OpenIddict to use the Entity Framework Core stores and models.
        // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
        options.UseEntityFrameworkCore()
               .UseDbContext<ServerDbContext>();
    })
    .AddServer(options =>
    {
        // Enable the authorization, logout, token and userinfo endpoints.
        options.SetAuthorizationEndpointUris("/connect/authorize")
                  .SetLogoutEndpointUris("/connect/logout")
                  .SetIntrospectionEndpointUris("/connect/introspect")
                  .SetTokenEndpointUris("/connect/token")
                  .SetUserinfoEndpointUris("/connect/userinfo")
                  .SetVerificationEndpointUris("/connect/verify");

        // Mark the "email", "profile" and "roles" scopes as supported scopes.
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);

        // Note: this sample only uses the authorization code flow but you can enable
        // the other flows if you need to support implicit, password or client credentials.
        options.AllowAuthorizationCodeFlow()
               .AllowClientCredentialsFlow();

        // Register the signing and encryption credentials.
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableLogoutEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserinfoEndpointPassthrough()
               .EnableStatusCodePagesIntegration();
    }).AddValidation(options =>
    {
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();

        // Register the ASP.NET Core host.
        options.UseAspNetCore();
    });

var app = builder.Build();
await IdentityConfigSeed.EnsureSeedData(app.Services, builder.Configuration);

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
    endpoints.MapDefaultControllerRoute();
    endpoints.MapRazorPages();
});

app.Run();