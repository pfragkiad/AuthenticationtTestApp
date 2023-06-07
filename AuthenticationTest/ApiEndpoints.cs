using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Identity.Web;
using Microsoft.Net.Http.Headers;
using System.Diagnostics;
using System.Security.Claims;

namespace AuthenticationTest;

public static class ApiEndpoints
{
    public const string AuthScheme = "cookiesda";
    public const string AuthScheme2 = "keftes";

    public static void AddCookieAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication(AuthScheme)
            .AddCookie(AuthScheme)
            .AddCookie(AuthScheme2);
            //.AddCookie(AuthScheme2, o=> o.Cookie.Name = "mpiftek")
            //.AddCookie(AuthScheme, o=>o.Cookie.Name = "ntomata");
    }

    public static void AddEndpoints(this IEndpointRouteBuilder builder)
    {
        builder.MapGet("/username",(HttpContext context) =>
        {
            //merges all cookies in a ; separated string
            //var cookie = context.Request.Headers.Cookie.ToArray();
            var user = context.User;
            //var claim = user.Claims.FirstOrDefault(c=>c.Type=="auth");
            //var id = claim.Value;
            var id = user.FindFirst("usr")?.Value ?? "Nothing!";
            return Results.Ok(id);
        }).RequireAuthorization("auth");

        builder.MapGet("/sweden",(HttpContext context) =>
        {
            //if (!context.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
            //    return Results.Unauthorized(); //401
            var user= context.User;

            //if(context.User.FindFirst("passport")?.Value=="eu")
          //  if (context.User.HasClaim("passport", "eu"))
                return Results.Ok("EUROPEAN!");

            ////return Results.Forbid(); //403
            //return Results.StatusCode(403);

        }).RequireAuthorization("eu passport");

        builder.MapGet("/uae",(HttpContext context) =>
        {
            //   if (!context.User.Identities.Any(x => x.AuthenticationType == AuthScheme2))
            //       return Results.Unauthorized(); //401
            var user = context.User;

            //if(context.User.FindFirst("passport")?.Value=="eu")
            //  if (context.User.HasClaim("passport", "asia"))
            return Results.Ok("asiannnn!");

            //return Results.Forbid(); //403
          //  return Results.StatusCode(403);

        }).RequireAuthorization("asia passport");


        builder.MapGet("/login",
            //(HttpContext context, AuthService auth) =>
            async (HttpContext context, string userName) =>
            {
                //auth.SignIn();

                string scheme = userName == "pavlos" ? AuthScheme : AuthScheme2;

                var claims = new List<Claim>();
                claims.Add(new Claim("usr", userName));
                claims.Add(new Claim("passport", userName == "pavlos" ? "eu" : "asia"));
                claims.Add(new Claim("scheme", scheme));

                var identity = new ClaimsIdentity(claims, scheme);
                var user = new ClaimsPrincipal(identity);

                await context.SignInAsync(scheme, user, new AuthenticationProperties
                {
                    IsPersistent = true,
                    AllowRefresh = true//,
                   // ExpiresUtc = DateTime.UtcNow.AddSeconds(20)
                });

                return Results.Ok(userName);
            }).AllowAnonymous();

        //sample: with principal
        //app.MapGet("/login", () => Results.SignIn(
        //    new ClaimsPrincipal(
        //        new ClaimsIdentity(
        //            new[] { new Claim("user_id", Guid.NewGuid().ToString()) }, "cookie")),
        //    authenticationScheme: "cookie"
        //    ));

    }

}
