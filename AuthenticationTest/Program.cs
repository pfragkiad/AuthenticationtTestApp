namespace AuthenticationTest;

public static class Program
{
    //https://www.youtube.com/watch?v=ExQJljpj1lY&list=PLOeFnOV9YBa4yaz-uIi5T4ZW3QQGHJQXi
    public static void Main(string[] args)
    {
        WebApplication app = GetApp(args);

        app.Run();
    }
}