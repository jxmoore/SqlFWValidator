using Newtonsoft.Json;
using System.Net.Http;
using System.Threading.Tasks;
using AzureSqlFWAuditor.Slack.Models;

namespace AzureSqlFWAuditor.Slack
{
    public class SlackClient 
    {
        private HttpClient _client;
        private readonly string _endpoint = "https://slack.com/api/chat.postMessage";

        public SlackClient(HttpClient client, string token)
        {
            _client = client;
            _client.DefaultRequestHeaders.Add("Authorization", "Bearer " + token);
        }

        public async Task<string> PostToSlackAsync(SlackPost body)
        {
            
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12 | System.Net.SecurityProtocolType.Tls11 | System.Net.SecurityProtocolType.Tls;
            var serialBody = JsonConvert.SerializeObject(body);
            var postBody = new StringContent(serialBody, System.Text.Encoding.UTF8, "application/json");
            var response = await _client.PostAsync(_endpoint, postBody);
            if (response.IsSuccessStatusCode)
                return "ok";

            return response.ReasonPhrase;
        }
    }
}
