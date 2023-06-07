using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Net.Http.Headers;
using System.Diagnostics;
using System.Security.Claims;

namespace AuthenticationTest;

public static class ApiEndpoints
{
    const string AuthScheme = "cookie";

    public static void AddCookieAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication().AddCookie(AuthScheme);
    }

    public static void AddEndpoints(this IEndpointRouteBuilder builder)
    {
        builder.MapGet("/username", (HttpContext context) =>
        {
            //merges all cookies in a ; separated string
            //var cookie = context.Request.Headers.Cookie.ToArray();
            var user = context.User;
            //var claim = user.Claims.FirstOrDefault(c=>c.Type=="auth");
            //var id = claim.Value;
            var id = user.FindFirst("usr").Value;
            return Results.Ok(id);
        });

        builder.MapGet("/sweden", (HttpContext context) =>
        {
            if (!context.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
                return Results.Unauthorized(); //401

            //if(context.User.FindFirst("passport")?.Value=="eu")
            if(context.User.HasClaim("passport","eu"))
                return Results.Ok("EUROPEAN!");

            //return Results.Forbid(); //403
            return Results.StatusCode(403);

        });

        builder.MapGet("/login",
            //(HttpContext context, AuthService auth) =>
            async (HttpContext context) =>
            {
                //auth.SignIn();

                var claims = new List<Claim>();
                claims.Add(new Claim("usr", "pavlos"));
                 claims.Add(new Claim("passport", "eu"));
               var identity = new ClaimsIdentity(claims, AuthScheme);
                var user = new ClaimsPrincipal(identity);

                await context.SignInAsync(AuthScheme, user);

                return new { Name = "Pavlos" };
            });

        //sample: with principal
        //app.MapGet("/login", () => Results.SignIn(
        //    new ClaimsPrincipal(
        //        new ClaimsIdentity(
        //            new[] { new Claim("user_id", Guid.NewGuid().ToString()) }, "cookie")),
        //    authenticationScheme: "cookie"
        //    ));

    }

}
