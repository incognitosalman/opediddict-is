using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Server.Auth.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.AspNetCore.Identity.UI.Services;
using Server.Auth.Helpers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
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
    .AddSignInManager();

builder.Services.AddOptions().AddLogging();
builder.Services.TryAddScoped<IUserValidator<IdentityUser>, UserValidator<IdentityUser>>();
builder.Services.TryAddScoped<IRoleValidator<IdentityRole>, RoleValidator<IdentityRole>>();
builder.Services.TryAddScoped<IPasswordValidator<IdentityUser>, PasswordValidator<IdentityUser>>();
builder.Services.TryAddScoped<IPasswordHasher<IdentityUser>, PasswordHasher<IdentityUser>>();
builder.Services.TryAddScoped<ILookupNormalizer, UpperInvariantLookupNormalizer>();
builder.Services.TryAddScoped<IUserConfirmation<IdentityUser>, DefaultUserConfirmation<IdentityUser>>();
builder.Services.TryAddScoped<IdentityErrorDescriber>();
builder.Services.TryAddScoped<IUserClaimsPrincipalFactory<IdentityUser>, UserClaimsPrincipalFactory<IdentityUser>>();
builder.Services.TryAddScoped<UserManager<IdentityUser>>();
builder.Services.TryAddScoped<RoleManager<IdentityRole>>();
builder.Services.TryAddTransient<IEmailSender, EmailSender>();


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
               .SetTokenEndpointUris("/connect/token")
               .SetUserinfoEndpointUris("/connect/userinfo");

        // Mark the "email", "profile", "roles", and "openid" scopes as supported scopes.
        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OpenId);

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
    endpoints.MapDefaultControllerRoute();
});
app.MapRazorPages();
app.Run();