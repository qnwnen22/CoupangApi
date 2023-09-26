using System;
using System.Net;
using System.Security.Cryptography;

namespace Coupang
{
    public class CoupangApi
    {
        public readonly string accessKey;
        public readonly string secretKey;

        public CoupangApi(string accessKey, string secretKey)
        {
            this.accessKey = accessKey;
            this.secretKey = secretKey;
        }

        private string GetHmac(string method, string path, string query)
        {
            string algorithm = "HmacSHA256";
            string datetime = DateTime.Now.ToUniversalTime().ToString("yyMMddTHHmmssZ");
            string message = GenerateFormattedMessage(datetime, method, path, query);

            string signature = CreateTokenByHMACSHA256(message);

            return GenerateFormattedHeader(algorithm, datetime, signature);
        }

        private string GenerateFormattedMessage(string datetime, string method, string path, string query)
        {
            return string.Format("{0}{1}{2}{3}", datetime, method, path, query);
        }

        private string GenerateFormattedHeader(string algorithm, string datetime, string signature)
        {
            return string.Format("CEA algorithm={0}, access-key={1}, signed-date={2}, signature={3}", algorithm, this.accessKey, datetime, signature);
        }

        private string CreateTokenByHMACSHA256(string message)
        {
            string secretKey = this.secretKey ?? "";
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(secretKey);
            var hmacsha256 = new HMACSHA256(keyByte);
            byte[] messageBytes = encoding.GetBytes(message);
            return ByteToString(hmacsha256.ComputeHash(messageBytes));
        }

        public string ByteToString(byte[] buff)
        {
            string sbinary = "";
            for (int i = 0; i < buff.Length; i++)
            {
                sbinary += buff[i].ToString("x2"); // hex format
            }
            return sbinary;
        }

        public HttpWebRequest CreateRequest(string address, string method)
        {
            var uri = new Uri(address);

            HttpWebRequest request = WebRequest.Create(address) as HttpWebRequest;

            request.Timeout = 10000;
            request.Method = method;

            request.ContentType = "application/json;charset=UTF-8";
            request.Headers["Authorization"] = GetHmac(method, uri.AbsolutePath, uri.Query);

            return request;
        }
    }
}
