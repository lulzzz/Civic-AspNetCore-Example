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

            // CREATING THE JWT
            // your private signing key from Civic
            const string privateKey = "e8593ad98db1dda0f57c16ef1f53c4c6b57fa35d9b5f82602353ccfb5a71f047";
            var privKeyInt = new Org.BouncyCastle.Math.BigInteger(+1, FromHexString(privateKey));
            var parameters = SecNamedCurves.GetByName("secp256r1");
            var qa = parameters.G.Multiply(privKeyInt);
            var privKeyX = qa.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned();
            var privKeyY = qa.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned();

            var privateKeyEcdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privKeyInt.ToByteArrayUnsigned(),
                Q = new ECPoint
                {
                    X = privKeyX,
                    Y = privKeyY
                }
            });

            var now = DateTime.UtcNow;
            var tokenHandler = new JwtSecurityTokenHandler();
            var signingCredentials = new SigningCredentials(new ECDsaSecurityKey(privateKeyEcdsa), SecurityAlgorithms.EcdsaSha256);

            var jwtHeader = new JwtHeader(signingCredentials);
            var jwtPayload = new JwtPayload(
                issuer: "rJ3fVI9rz",
                audience: "https://api.civic.com/sip",
                claims: new List<Claim> { new Claim("sub", "rJ3fVI9rz"), new Claim("jti", Guid.NewGuid().ToString()) },
                notBefore: null,
                expires: now.AddMinutes(5),
                issuedAt: now);
            jwtPayload.Add("data", new Dictionary<string, string> { { "method", "POST" }, { "path", "scopeRequest/authCode" } });

            var exchangeToken = tokenHandler.WriteToken(new JwtSecurityToken(jwtHeader, jwtPayload));

            // CREATING THE MESSAGE DIGEST
            // your secret from Civic
            const string secret = "482283244e2e8082d6f1c3ef288930ce";

            var data = JsonConvert.SerializeObject(new { authToken = model.AuthCode });

            var secretBytes = Encoding.Default.GetBytes(secret);
            var dataBytes = Encoding.Default.GetBytes(data);
            var hmac = new HMACSHA256(secretBytes);
            var hashAsBytes = hmac.ComputeHash(dataBytes);
            var hash = Convert.ToBase64String(hashAsBytes);

            // REQUESTING USER DATA
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Civic", $"{exchangeToken}.{hash}");
            var responseMessage = await httpClient.PostAsync("https://api.civic.com/sip/prod/scopeRequest/authCode", new StringContent(data, Encoding.UTF8, "application/json"));

            var response = await responseMessage.Content.ReadAsStringAsync();

            // VERIFYING THE JWT SIGNATURE
            const string civicAuthServerPublicKey = "049a45998638cfb3c4b211d72030d9ae8329a242db63bfb0076a54e7647370a8ac5708b57af6065805d5a6be72332620932dbb35e8d318fce18e7c980a0eb26aa1";
            var pubKeyX = FromHexString(civicAuthServerPublicKey).Skip(1).Take(32).ToArray();
            var pubKeyY = FromHexString(civicAuthServerPublicKey).Skip(33).ToArray();

            var publicKeyEcdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.CreateFromFriendlyName("secp256r1"),
                Q = new ECPoint
                {
                    X = pubKeyX,
                    Y = pubKeyY
                }
            });

            var jObject = JObject.Parse(response);
            var jToken = jObject["data"];
            var jwt = jToken.Value<string>();

            var claimsPrincipal = tokenHandler.ValidateToken(jwt, new TokenValidationParameters
            {
                ValidIssuer = "civic-sip-hosted-service",
                ValidateIssuer = true,
                ValidAudience = "https://api.civic.com/sip/",
                ValidateAudience = true,
                ValidateLifetime = true,
                IssuerSigningKey = new ECDsaSecurityKey(publicKeyEcdsa)
            }, out var _);

            // DECRYPTING THE DATA
            var loadedData = claimsPrincipal.FindFirst("data").Value;

            var iv = FromHexString(loadedData.Substring(0, 32));
            var encryptedData = Convert.FromBase64String(loadedData.Substring(32));

            string plainTextUserData;

            var aes = Aes.Create();
            aes.IV = iv;
            aes.Key = FromHexString(secret);

            using (aes)
            using (var memoryStream = new MemoryStream(encryptedData))
            using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read))
            using (var srDecrypt = new StreamReader(cryptoStream))
                plainTextUserData = srDecrypt.ReadToEnd();

            var userData = JsonConvert.DeserializeObject<List<UserData>>(plainTextUserData);

            // AUTHENTICATING THE USER
            var claimsIdentity = new ClaimsIdentity(userData.Select(x => new Claim(x.Label, x.Value)).ToList(), "cookie");
            claimsIdentity.AddClaim(new Claim("userId", jObject["userId"].Value<string>()));

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
