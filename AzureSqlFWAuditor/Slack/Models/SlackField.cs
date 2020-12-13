
using Newtonsoft.Json;

namespace AzureSqlFWAuditor.Slack.Models
{
    public class SlackField
    {
        [JsonProperty("title")]
        public string Title { get; set; }
        [JsonProperty("value")]
        public string Value { get; set; }
        [JsonProperty("short")]
        public bool Short {get;set;}
    }
}
