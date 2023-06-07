using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Net.Http.Headers;
using System.Diagnostics;
using System.Security.Claims;

namespace AuthenticationTest;

public static class ApiEndpoints
{
    public static void AddCookieAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication().AddCookie("cookie");
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

        builder.MapGet("/login",
            //(HttpContext context, AuthService auth) =>
            async (HttpContext context) =>
            {
                //auth.SignIn();

                var claims = new List<Claim>();
                claims.Add(new Claim("usr", "pavlos"));



                await context.SignInAsync("cookie", new System.Security.Claims.ClaimsPrincipal());

                return new { Name = "Pavlos" };
            });

#pragma warning disable S125 // Sections of code should not be commented out
        //sample: with principal
        //app.MapGet("/login", () => Results.SignIn(
        //    new ClaimsPrincipal(
        //        new ClaimsIdentity(
        //            new[] { new Claim("user_id", Guid.NewGuid().ToString()) }, "cookie")),
        //    authenticationScheme: "cookie"
        //    ));
#pragma warning restore S125 // Sections of code should not be commented out

    }

}
