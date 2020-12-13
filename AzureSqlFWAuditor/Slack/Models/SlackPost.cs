using Newtonsoft.Json;
using System.Collections.Generic;

namespace AzureSqlFWAuditor.Slack.Models
{
    public class SlackPost 
    {
        [JsonProperty("attachments")]
        public List<SlackAttachment> Attachments { get; set; }
        [JsonProperty("channel")]
        public string Channel { get; set; }
        [JsonProperty("text")]
        public string Text { get; set; }

    }

}
