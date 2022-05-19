using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
        .AddCookie(options =>
        {
            options.LoginPath = "/login";
            options.ExpireTimeSpan = TimeSpan.FromMinutes(50);
            options.SlidingExpiration = false;
        })

        .AddOpenIdConnect(options =>
        {
            // Note: these settings must match the application details
            // inserted in the database at the server level.
            options.ClientId = "mvc";
            options.ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654";

            options.RequireHttpsMetadata = false;
            options.GetClaimsFromUserInfoEndpoint = true;
            options.SaveTokens = true;

            // Use the authorization code flow.
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;

            // Note: setting the Authority allows the OIDC client middleware to automatically
            // retrieve the identity provider's configuration and spare you from setting
            // the different endpoints URIs or the token validation parameters explicitly.
            options.Authority = "https://localhost:44380/";

            options.Scope.Add("email");
            options.Scope.Add("roles");

            // Disable the built-in JWT claims mapping feature.
            options.MapInboundClaims = true;

            options.TokenValidationParameters.NameClaimType = "name";
            options.TokenValidationParameters.RoleClaimType = "role";
        });
// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddHttpClient();
var app = builder.Build();

app.UseDeveloperExceptionPage();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseEndpoints(options =>
{
    options.MapControllers();
    options.MapDefaultControllerRoute();
}); 
app.Run();
