using Newtonsoft.Json;
using System.Collections.Generic;

namespace AzureSqlFWAuditor.Slack.Models
{
    public class SlackAttachment
    {
        [JsonProperty("color")]
        public string Color {get;set ;}
        [JsonProperty("fallback")]
        public string Fallback { get; set; }
        [JsonProperty("title")]
        public string Title { get; set; }
        [JsonProperty("fields")]
        public List<SlackField> Fields { get; set; }
        [JsonProperty("actions")]
        public List<SlackAction> Actions { get; set; }
    }
}
