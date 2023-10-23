using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using secure_reverse_proxy;
using database.Redis;
using StackExchange.Redis;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

internal class Program
{

    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Host.ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddConsole();
            });
        var services = builder.Services;
        var configuration = builder.Configuration;

        RedisHub mRedisHub = new (configuration);

        services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

        X509Certificate2 keyCertificate = new X509Certificate2(configuration["PfxCertfile"], configuration["PfxCertPassword"]);
        var dataProtection = services.AddDataProtection()
                .PersistKeysToStackExchangeRedis(mRedisHub.Connection, "DataProtection-Keys")
                .ProtectKeysWithCertificate(keyCertificate);
                //.UnprotectKeysWithAnyCertificate(new X509Certificate2[] { keyCertificate });



        //var decryptor = new CookieDecryptor(mRedisHub, configuration["PfxCertfile"], configuration["PfxCertPassword"]);
        //services.AddSingleton<CookieDecryptor>(decryptor);

        var app = builder.Build();

        app.UseRouting();
        
        app.UseMiddleware<CookieFilterMiddleware>();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapReverseProxy();
        });
       
        app.Run("http://0.0.0.0:4000");
    }
}