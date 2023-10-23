

using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using database.Redis;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Extensions;

namespace secure_reverse_proxy
{
    public class CookieFilterMiddleware
    {
        private readonly List<string> _allowWithoutCookies = new(new string[]{
        "/account/Login",
        "/account/TwoFactorAuth",
        "/account/Eula",
        "/account/_content/",
        "/account/lib/",
        "/account/css/",
        "/account/images/",
        "/account/js/",
        "/_content/"
    });

        private readonly List<string> _neededCookieNames = new(new string[]{
        "ANA.SS",
        "SERVICES.ANA"
    });
        private readonly List<HttpStatusCode> _redirectCodes = new(new HttpStatusCode[]{
            HttpStatusCode.Moved,
            HttpStatusCode.MovedPermanently,
            HttpStatusCode.Redirect,
            HttpStatusCode.SeeOther,
            HttpStatusCode.TemporaryRedirect
        });

        private readonly RequestDelegate _next;
        private readonly ILogger<CookieFilterMiddleware> _logger;
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private readonly IConfiguration _configuration;
        private readonly IDataProtector _dataProtector;
        const string cookieTest = "CfDJ8OsPqjRjM6REsnPdVo04thrxY8blE2agEnvC_K-UsmVq16x_l1Y96E--7FipQtGbSW1Fp8V-9vzYVZ4tV49PoQT7bogq3TSmSCFKZw1NybPo3J6iTyVXzazNdHtJ0AlDRzRG4itWU5mZ3X7goohxLX7nwwkkrJyLmCzGIj5k9dkUnwTMLwz0Gs9mawfpecEu5GkjHpbONPILtwg7LYspeBTHxrfAgeBAYQIBEOUeqNaPZQMhlsl87-a_F7vpN2PYYadafA3IwL1EfVVUQmVkrCMUDgkfI74XSNAA0gDUkACigI1PRc8bBCQMq6ANfgdpBs_xFpoqDrqwWJ1wH4ppcT7pXp2tP2unmd6jdHkIBFgegGwuUOuABktK9newhOhzo_NRImeiQxBXcfnCk76QXcUdPzsER9J2d7BUrPw8xMAXWMhiibBIAqvfBHQc2XCNME0cTcuvX9teTwTT7KSp2sGgAlJnNsmTlA2iVCyvYyjXgsiuvoSTD1315XzX5pUCCz-p0zW7JEbu1y-VDDsebe3ss3xbOXH-j4pmGQmEoyALfZr_l8nujgZc-mjovI1qqK1jGg27L-X4iy2ANzLG2fsbqkzRBgdbPYpsN5wTm76W5tkYFCG9SUZSO5ugSWJfU8jRFCXr7SbWU6iIG8hdZGQ5pGLlJJ455pIhUS4OQYjESjSfegtgZmKH5nx9BVYWLaI-yoDX26bHJtPlaKC1fxV2mH99vuodS2Beu2q9zOOd";
        private readonly CookieDecryptor _cookieDecryptor;
        public CookieFilterMiddleware(RequestDelegate next,
                                      ILogger<CookieFilterMiddleware> logger,
                                      IConfiguration configuration,
                                      IDataProtectionProvider dataProteccionProvider
                                      /*CookieDecryptor cookieDecryptor*/)
        {
            _next = next;
            _logger = logger;
            _dataProtectionProvider = dataProteccionProvider;
            _configuration = configuration;
            _dataProtector = _dataProtectionProvider.CreateProtector("ANA.SS");
            _dataProtector.Unprotect(cookieTest);
            //_cookieDecryptor = cookieDecryptor;
            //TestCookie();
        }

        byte[] ConvertToMultiply16 (byte[]payload)
        {
            int cipherTextLength = payload.Length;
            int remainder = cipherTextLength % 16;
            if (remainder != 0)
            {
                cipherTextLength += 16 - remainder;
            }
            byte[] cipherTextComplete = new byte[cipherTextLength];
            Array.Copy(payload, cipherTextComplete, payload.Length);
            return cipherTextComplete;
        }
        byte[] ToByteArrayFromBase64URLString (string base64UrlString)
        {
            string base64String = base64UrlString.Replace('-', '+').Replace('_', '/');
            byte [] byteArr = Convert.FromBase64String(base64String);
            
            return ConvertToMultiply16 (byteArr);
        }
        public void TestCookie ()
        {
            var res = _cookieDecryptor.DecryptBaseURL64String(cookieTest);
            _logger.LogInformation(res);
        }

        string DecryptCookie(string cookieValue)
        {
            try
            {
                var decryptedValue = _dataProtector.Unprotect(cookieValue);
                return decryptedValue;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting cookie");
                return null;
            }
        }
        bool HasNeededCookies(IRequestCookieCollection cookies)
        {
            foreach (var cookieName in _neededCookieNames)
            {
                if (!cookies.ContainsKey(cookieName))
                    return false;
            }
            return true;
        }
        public async Task Invoke(HttpContext context)
        {
            var stopwatch = Stopwatch.StartNew();

            var logTrace = new Dictionary<string, string>
            {
                ["Method"] = context.Request.Method,
                ["Host"] = context.Request.Host.Value,
                ["Path"] = context.Request.Path.Value ?? "unknown",
                ["IP"] = context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                ["ClientIP"] = context.Request.Headers["X-Real-Ip"],
                ["ForwarderFor"] = context.Request.Headers["X-Forwarded-For"],
                ["ClientCert"] = String.IsNullOrEmpty(context.Request.Headers[""]) ? "" : "CLIENT-CERT"

            };
            if (!_allowWithoutCookies.Any(p => context.Request.Path.Value?.StartsWith(p) ?? false))
            {
                logTrace["SecureContext"] = "true";
                logTrace["Forbidden"] = "false";
                if (!HasNeededCookies(context.Request.Cookies))
                {
                    logTrace["Forbidden"] = "true";
                    context.Response.StatusCode = StatusCodes.Status302Found;
                    context.Response.Headers["Location"] = "/account/Login";

                    await context.Response.WriteAsync("");
                }
                else
                {
                    string cookieValue = context.Request.Cookies["SERVICES.ANA"];
                    if (cookieValue is not null)
                    {
                        string coookieContent = DecryptCookie(cookieValue);
                        await _next(context);
                    }
                    else
                    {
                        logTrace["Forbidden"] = "true";
                        context.Response.StatusCode = StatusCodes.Status302Found;
                        context.Response.Headers["Location"] = "/account/Login";
                        await context.Response.WriteAsync("");
                    }
                }
            }
            else
            {
                logTrace["SecureContext"] = "false";
                await _next(context);
            }
            stopwatch.Stop();
            logTrace["ElapsedTime"] = $"{stopwatch.ElapsedMilliseconds} ms";
            logTrace["ReturnCode"] = $"{context.Response.StatusCode}";
            if (_redirectCodes.Contains((HttpStatusCode)context.Response.StatusCode))
                logTrace["RedirectedTo"] = context.Response.Headers["Location"];
            else
                logTrace["RedirectedTo"] = "";
            try
            {
                _logger.LogInformation(JsonSerializer.Serialize(logTrace));
            }
            catch (Exception)
            { }
        }
    }
}