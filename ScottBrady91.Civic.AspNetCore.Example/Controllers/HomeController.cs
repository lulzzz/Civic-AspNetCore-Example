using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Sec;
using ScottBrady91.Civic.AspNetCore.Example.Models;

namespace ScottBrady91.Civic.AspNetCore.Example.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            if (string.IsNullOrWhiteSpace(model?.AuthCode)) return BadRequest();

            const string privateKey = "e8593ad98db1dda0f57c16ef1f53c4c6b57fa35d9b5f82602353ccfb5a71f047";
            const string civicAuthServerPublicKey = "049a45998638cfb3c4b211d72030d9ae8329a242db63bfb0076a54e7647370a8ac5708b57af6065805d5a6be72332620932dbb35e8d318fce18e7c980a0eb26aa1";
            const string secret = "482283244e2e8082d6f1c3ef288930ce";

            // generate JWT - sign using private key & ECDSA
            var token = CreateSignedJwt(LoadPrivateKey(FromHexString(privateKey)));
            
            // generate body
            var data = JsonConvert.SerializeObject(new { authToken = model.AuthCode });

            // HMAC of body
            var hash = CreateHash(secret, data);

            // exchange auth code
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Civic", $"{token}.{hash}");
            var responseMessage = await httpClient.PostAsync("https://api.civic.com/sip/prod/scopeRequest/authCode",
                new StringContent(data, Encoding.UTF8, "application/json"));

            var response = await responseMessage.Content.ReadAsStringAsync();

            // extract data (JWT) from response
            var jObject = JObject.Parse(response);
            var jToken = jObject["data"];
            var jwt = jToken.Value<string>();

            // verify & extract jwt
            var claimsPrincipal = VerifySignedJwt(LoadPublicKey(FromHexString(civicAuthServerPublicKey)), jwt);

            // decrypt data
            var loadedData = claimsPrincipal.FindFirst("data");
            var userData = DecryptData(secret, loadedData.Value);

            // sign in user
            var claimsIdentity = new ClaimsIdentity(userData.Select(x => new Claim(x.Label, x.Value)).ToList(), "cookie");
            await HttpContext.SignInAsync("cookie", new ClaimsPrincipal(claimsIdentity));

            return Ok();
        }

        private static byte[] FromHexString(string hex)
        {
            var numberChars = hex.Length;
            var hexAsBytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);

            return hexAsBytes;
        }

        private static ECDsa LoadPrivateKey(byte[] key)
        {
            var privKeyInt = new Org.BouncyCastle.Math.BigInteger(+1, key);
            var parameters = SecNamedCurves.GetByName("secp256r1");
            var qa = parameters.G.Multiply(privKeyInt);
            var pubKeyX = qa.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned();
            var pubKeyY = qa.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned();

            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privKeyInt.ToByteArrayUnsigned(),
                Q = new ECPoint
                {
                    X = pubKeyX,
                    Y = pubKeyY
                }
            });
        }

        private static ECDsa LoadPublicKey(byte[] key)
        {
            var x = key.Skip(1).Take(32).ToArray();
            var y = key.Skip(33).ToArray();

            return ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.CreateFromFriendlyName("secp256r1"),
                Q = new ECPoint
                {
                    X = x,
                    Y = y
                }
            });
        }

        private static string CreateSignedJwt(ECDsa eCDsa)
        {
            var now = DateTime.UtcNow;
            var tokenHandler = new JwtSecurityTokenHandler();
            var signingCredentials = new SigningCredentials(new ECDsaSecurityKey(eCDsa), SecurityAlgorithms.EcdsaSha256);

            var jwtHeader = new JwtHeader(signingCredentials);
            var jwtPayload = new JwtPayload(
                issuer: "rJ3fVI9rz",
                audience: "https://api.civic.com/sip",
                claims: new List<Claim> {new Claim("sub", "rJ3fVI9rz"), new Claim("jti", Guid.NewGuid().ToString())},
                notBefore: null,
                expires: now.AddMinutes(5),
                issuedAt: now);
            jwtPayload.Add("data", new Dictionary<string, string> { { "method", "POST" }, { "path", "scopeRequest/authCode" } });

            return tokenHandler.WriteToken(new JwtSecurityToken(jwtHeader, jwtPayload));
        }

        private static string CreateHash(string secret, string data)
        {
            var secretBytes = Encoding.Default.GetBytes(secret);
            var dataBytes = Encoding.Default.GetBytes(data);
            var hmac = new HMACSHA256(secretBytes);
            var hash = hmac.ComputeHash(dataBytes);
            return Convert.ToBase64String(hash);
        }

        private static ClaimsPrincipal VerifySignedJwt(ECDsa eCDsa, string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var claimsPrincipal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = "civic-sip-hosted-service",
                ValidateIssuer = true,
                ValidAudience = "https://api.civic.com/sip/",
                ValidateAudience = true,
                ValidateLifetime = true,
                IssuerSigningKey = new ECDsaSecurityKey(eCDsa)
            }, out var _);

            return claimsPrincipal;
        }

        private static List<UserData> DecryptData(string secret, string data)
        {
            var iv = FromHexString(data.Substring(0, 32));
            var encryptedData = Convert.FromBase64String(data.Substring(32));

            string plainTextUserData;

            var aes = Aes.Create();
            aes.IV = iv;
            aes.Key = FromHexString(secret);

            using (aes)
            using (var memoryStream = new MemoryStream(encryptedData))
            using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read))
            using (var srDecrypt = new StreamReader(cryptoStream))
                plainTextUserData = srDecrypt.ReadToEnd();

            return JsonConvert.DeserializeObject<List<UserData>>(plainTextUserData);
        }

        public class LoginModel
        {
            public string AuthCode { get; set; }
        }

        private class UserData
        {
            public string Label { get; set; }
            public string Value { get; set; }
            public bool IsValid { get; set; }
            public bool IsOwner { get; set; }
        }
    }
}
