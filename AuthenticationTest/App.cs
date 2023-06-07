global using static AuthenticationTest.App;
using Azure;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;

//[assembly: CLSCompliant(true)]
namespace AuthenticationTest;

public static class App
{
    public static WebApplication GetApp(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        //builder.Services.AddCookieAuthentication();

        //builder.Services.AddDataProtection();
        //builder.Services.AddHttpContextAccessor();
        //builder.Services.AddScoped<AuthService>();

        var app = builder.Build();

        //app.Use((context, next) =>
        //{
        //    var cookies = context.Request.Cookies;
        //    var authCookie = cookies.FirstOrDefault(x => x.Key == "auth").Value;
        //    if (authCookie is null) return Task.FromResult(Results.Unauthorized());

        //    var provider = context.RequestServices.GetRequiredService<IDataProtectionProvider>();
        //    var protector = provider.CreateProtector("auth-cookie");
        //    string authText = protector.Unprotect(authCookie);
        //    string[] tokens = authText.Split(':');
        //    string key = tokens[0];
        //    string value= tokens[1];

        //    var claims = new List<Claim>();
        //    claims.Add(new Claim(key, value));
        //    var identity = new ClaimsIdentity(claims);
        //    context.User = new ClaimsPrincipal(identity);
        //    //context.User.AddIdentity(identity);

        //    return next();
        //});

        app.UseAuthentication(); //equivalent middleware

        app.AddEndpoints();

        return app;
    }
}
