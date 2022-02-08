using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;

namespace TestConsole123
{
    /// <summary>
    /// Tiện ích Aws
    /// </summary>
    /// Created by: HTKIEN1 (07/09/2021)
    public static class AwsUtil
    {
        private const string ALGORITHM = "AWS4-HMAC-SHA256";
        private const string EMPTY_STRING_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        /// <summary>
        /// In ra AWS signature, header authorization
        /// </summary>
        /// <param name="HttpRequestMessage">request tạo sẵn</param>
        /// <param name="service">Tên service aws sử dụng</param>
        /// <param name="region">Tên khu vực aws sử dụng</param>
        /// <param name="accessKey">access key</param>
        /// <param name="secretKey">access secret</param>
        /// <returns>Dictionary header authorization</returns>
        /// Created by: HTKIEN1 (07/09/2021)
        public static async Task<Dictionary<string, string>> GenerateHeaderAuthorization(HttpRequestMessage request, string service, string region, string accessKey, string secretKey)
        {
            Dictionary<string, string> headers = request.Headers.ToDictionary(a => a.Key, a => string.Join(";", a.Value));
            List<TemplateMetaData> result = new();
            string nextToken = string.Empty;
            var client = new HttpClient();
            while (true)
            {

                await Task.Delay(2400);
                if (!String.IsNullOrEmpty(nextToken))
                {
                    nextToken = WebUtility.UrlEncode(nextToken);

                }
                request = new HttpRequestMessage
                {
                    Method = HttpMethod.Get,
                    RequestUri = new Uri($"https://email.ap-southeast-1.amazonaws.com/v2/email/templates?NextToken={nextToken}&PageSize=100"),
                };

                request = await Sign(request, service, region, accessKey, secretKey);

                var response = await client.SendAsync(request);
                var responseStr = await response.Content.ReadAsStringAsync();
                var lstTemplate = JsonSerializer.Deserialize<ResultFromAWS>(responseStr);

                if (lstTemplate.TemplatesMetadata.Count >= 100)
                {
                    for (int i = 0; i < lstTemplate.TemplatesMetadata.Count; i++)
                    {
                        result.Add(lstTemplate.TemplatesMetadata[i]);

                    }
                    Console.WriteLine("Số lượng template: " + result.Count);
                    nextToken = lstTemplate.NextToken;
                    // if (result.Count == 2000)
                    // {
                    //     break;
                    // }
                }
                else
                {
                    Console.WriteLine("Hết template");
                    break;
                }
            }
            for (int i = 100; i < result.Count; i++)
            {
                await Task.Delay(600);
                var request1 = new HttpRequestMessage
                {
                    Method = HttpMethod.Delete,
                    RequestUri = new Uri("https://email.ap-southeast-1.amazonaws.com/v2/email/templates/" + result[i].TemplateName),
                };
                request1 = await Sign(request1, service, region, accessKey, secretKey);
                var response1 = await client.SendAsync(request1);
                var responseStr1 = await response1.Content.ReadAsStringAsync();
                Console.WriteLine(responseStr1 + ", xóa template name:" + result[i].TemplateName);
            }

            return headers;
        }

        /// <summary>
        /// Hàm trả về chuỗi hash sha256
        /// </summary>
        /// <param name="bytesToHash">Chuỗi byte để hash</param>      
        /// <returns>Chuỗi hash</returns>
        /// Created by: HTKIEN1 (07/09/2021)
        private static string Hash(byte[] bytesToHash)
        {
            var _sha256 = SHA256.Create();
            var result = _sha256.ComputeHash(bytesToHash);
            return ToHexString(result);
        }

        /// <summary>
        /// Hàm trả về chuỗi hex string
        /// </summary>
        /// <param name="array">mảng byte cần mã hóa</param>      
        /// <returns>Chuỗi hex string</returns>
        /// Created by: HTKIEN1 (07/09/2021)
        private static string ToHexString(IReadOnlyCollection<byte> array)
        {
            var hex = new StringBuilder(array.Count * 2);
            foreach (var b in array)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }

        /// <summary>
        /// Hàm trả về Hmacsha256 theo chuẩn AWS
        /// </summary>
        /// <param name="key">Khóa truyền vào</param>
        /// <param name="data">Dữ liệu truyền vào</param>  
        /// <returns>Mảng byte Hmacsha256</returns>
        /// Created by: HTKIEN1 (07/09/2021)
        private static byte[] HmacSha256(byte[] key, string data)
        {
            var hashAlgorithm = new HMACSHA256(key);

            return hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        /// <summary>
        /// Hàm trả về signature key AWS
        /// </summary>
        /// <param name="array">mảng byte cần mã hóa</param>      
        /// <returns>mảng byte signature AWS</returns>
        /// Created by: HTKIEN1 (07/09/2021)
        private static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
        {
            var kSecret = Encoding.UTF8.GetBytes("AWS4" + key);
            var kDate = HmacSha256(kSecret, dateStamp);
            var kRegion = HmacSha256(kDate, regionName);
            var kService = HmacSha256(kRegion, serviceName);
            var kSigning = HmacSha256(kService, "aws4_request");
            return kSigning;
        }

        /// <summary>
        /// Hàm xử lý logic in ra chữ kí aws
        /// </summary>
        /// <param name="HttpRequestMessage">request tạo sẵn</param>
        /// <param name="service">Tên service aws sử dụng</param>
        /// <param name="region">Tên khu vực aws sử dụng</param>
        /// <param name="accessKey">access key</param>
        /// <param name="secretKey">access secret</param>    
        /// <param name="timeOffset">thời gian trì hoãn nếu có</param>
        /// <returns>mảng byte signature AWS</returns>
        /// Created by: HTKIEN1 (07/09/2021)
        public static async Task<HttpRequestMessage> Sign(HttpRequestMessage request, string service, string region, string accessKey, string secretKey, TimeSpan? timeOffset = null)
        {
            if (string.IsNullOrEmpty(service))
            {
                throw new ArgumentOutOfRangeException(nameof(service), service, "Not a valid service.");
            }

            if (string.IsNullOrEmpty(region))
            {
                throw new ArgumentOutOfRangeException(nameof(region), region, "Not a valid region.");
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (request.Headers.Host == null)
            {
                request.Headers.Host = request.RequestUri.Host;
            }

            var content = new byte[0];
            if (request.Content != null)
            {
                content = await request.Content.ReadAsByteArrayAsync();
            }

            var payloadHash = EMPTY_STRING_HASH;
            if (content.Length != 0)
            {
                payloadHash = Hash(content);
            }

            if (request.Headers.Contains("x-amz-content-sha256") == false)
                request.Headers.Add("x-amz-content-sha256", payloadHash);

            var t = DateTimeOffset.UtcNow;
            if (timeOffset.HasValue)
                t = t.Add(timeOffset.Value);
            var amzDate = t.ToString("yyyyMMddTHHmmssZ");
            request.Headers.Add("x-amz-date", amzDate);
            var dateStamp = t.ToString("yyyyMMdd");

            var canonicalRequest = new StringBuilder();
            canonicalRequest.Append(request.Method + "\n");

            canonicalRequest.Append(string.Join("/", request.RequestUri.AbsolutePath.Split('/').Select(Uri.EscapeDataString)) + "\n");

            var canonicalQueryParams = GetCanonicalQueryParams(request);

            canonicalRequest.Append(canonicalQueryParams + "\n");

            var signedHeadersList = new List<string>();

            foreach (var header in request.Headers.OrderBy(a => a.Key.ToLowerInvariant(), StringComparer.OrdinalIgnoreCase))
            {
                canonicalRequest.Append(header.Key.ToLowerInvariant());
                canonicalRequest.Append(":");
                canonicalRequest.Append(string.Join(",", header.Value.Select(s => s.Trim())));
                canonicalRequest.Append("\n");
                signedHeadersList.Add(header.Key.ToLowerInvariant());
            }

            canonicalRequest.Append("\n");

            var signedHeaders = string.Join(";", signedHeadersList);

            canonicalRequest.Append(signedHeaders + "\n");
            canonicalRequest.Append(payloadHash);

            var credentialScope = $"{dateStamp }/{region}/{service}/aws4_request";

            var stringToSign = $"{ALGORITHM}\n{amzDate}\n{credentialScope}\n" + Hash(Encoding.UTF8.GetBytes(canonicalRequest.ToString()));

            var signingKey = GetSignatureKey(secretKey, dateStamp, region, service);
            var signature = ToHexString(HmacSha256(signingKey, stringToSign));

            request.Headers.TryAddWithoutValidation("Authorization", $"{ALGORITHM} Credential={accessKey}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}");

            return request;
        }

        private static string GetCanonicalQueryParams(HttpRequestMessage request)
        {
            var values = new SortedDictionary<string, IEnumerable<string>>(StringComparer.Ordinal);

            var querystring = HttpUtility.ParseQueryString(request.RequestUri.Query);
            foreach (var key in querystring.AllKeys)
            {
                if (key == null)//Handles keys without values
                {
                    values.Add(Uri.EscapeDataString(querystring[key]), new[] { $"{Uri.EscapeDataString(querystring[key])}=" });
                }
                else
                {
                    // Handles multiple values per query parameter
                    var queryValues = querystring[key].Split(',')
                        // Order by value alphanumerically (required for correct canonical string)
                        .OrderBy(v => v)
                        // Query params must be escaped in upper case (i.e. "%2C", not "%2c").
                        .Select(v => $"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(v)}");

                    values.Add(Uri.EscapeDataString(key), queryValues);
                }
            }

            var queryParams = values.SelectMany(a => a.Value);
            var canonicalQueryParams = string.Join("&", queryParams);
            return canonicalQueryParams;
        }

    }
}
