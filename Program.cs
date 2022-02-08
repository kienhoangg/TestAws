using System;
using System.Net.Sockets;
using System.IO;
using System.Text;
using Aws4RequestSigner;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;


namespace TestConsole
{
    class Program
    {
        static async Task Main(string[] args)
        {

            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri("https://email.ap-southeast-1.amazonaws.com/v2/email/templates?PageSize=100"),
            };
            var abc = await TestConsole123.AwsUtil.GenerateHeaderAuthorization(request, "ses", "ap-southeast-1", "AKIA4FY2PST5BYF75SH4", "3JeS/QP5VbfKoBPktZVfogNo+Jo47Xz8FpGH1Yr7");
            //var abc2 = await AwsUtil2.GenerateHeaderAuthorization(request, "ses", "ap-southeast-1", "AKIA4FY2PST5BYF75SH4", "3JeS/QP5VbfKoBPktZVfogNo+Jo47Xz8FpGH1Yr7");
            Console.WriteLine(JsonSerializer.Serialize(abc));
            //   Console.WriteLine(JsonSerializer.Serialize(abc2));

            Console.ReadKey();
        }


    }
}
