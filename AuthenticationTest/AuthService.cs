using Microsoft.AspNetCore.DataProtection;

namespace AuthenticationTest;

public class AuthService
{
    private readonly IDataProtectionProvider _provider;
    private readonly IHttpContextAccessor _accessor;

    public AuthService(IDataProtectionProvider provider, IHttpContextAccessor accessor)
    {
        _provider = provider;
        _accessor = accessor;
    }

    public void SignIn()
    {
        var protector = _provider.CreateProtector("auth-cookie");


        //https://learn.microsoft.com/en-us/aspnet/web-api/overview/advanced/http-cookies
        _accessor.HttpContext.Response.Cookies.Append("auth", protector.Protect("usr:pavlos2"));
        //context.Response.Cookies.Append("auth", "usr:pavlos2");

        //context.Response.Headers["set-cookie"] = "auth=usr:pavlos";

    }
}
