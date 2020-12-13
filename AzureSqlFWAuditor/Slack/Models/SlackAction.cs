using Newtonsoft.Json;

namespace AzureSqlFWAuditor.Slack.Models
{
    public class SlackAction
    {
        [JsonProperty("type")]
        public string Type { get; set; }
        [JsonProperty("text")]
        public string Text { get; set; }
        [JsonProperty("url")]
        public string Url { get; set; }
    }
}
