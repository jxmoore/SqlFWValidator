using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


// These classes represent the JSON body of the POST that will be sent to slack. 


namespace SQLIpRange
{
    // Maps to the 'field' portion of the JSON body
    public class field
    {
        private string _title;
        private string _value;
        private bool _short;

        public string title
        {
            get => _title;
            set { _title = value; } 
        }
        public string value
        {
            get => _value;
            set { _value = value; }
        }
        public bool @short
        {
            get => _short;
            set { _short = value; }
        }
        public field()
        {
            title = "Priority";
            @short = false;
        }
    }

    // Maps to the 'Attachment' portion of the JSON body
    public class attachment
    {
        private string _fallback;
        private string _color;
        private string _author_link;
        private string _text;
        private List<field> _fields;
        private string _thumb_url;
        private string _footer;
        private string _footer_icon;
        private string _ts;

        public string fallback
        {
            get => _fallback;
            set { _fallback = value; }
        }
        public string color
        {
            get => _color;
            set { _color = value; }
        }
        public string author_link
        {
            get => _author_link;
            set { _author_link = value; }
        }
        public string text
        {
            get => _text;
            set { _text = value; }
        }
        public List<field> fields
        {
            get => _fields;
            set { _fields = value; }
        }
        public string thumb_url
        {
            get => _thumb_url;
            set { _thumb_url = value; }
        }
        public string footer
        {
            get => _footer;
            set { _footer = value; }
        }
        public string footer_icon
        {
            get => _footer_icon;
            set { _footer_icon = value; }
        }
        public string ts
        {
            get => _ts;
            set { _ts = value; }
        }
        public attachment()
        {
            fields = new List<field>();
            author_link = "https://github.com/jxmoore";
            thumb_url = "https://dotnetfoundation.org/img/dot_bot.png";
            footer_icon = "https://dotnetfoundation.org/img/dot_bot.png";
            color = "#900c3F";
            ts = DateTime.Now.ToString();
            footer = "SQL FW Validator";
            fallback = "Azure SQL PAAS Pulic Firewall Rules Alert";
            text = "*The following server(s) have firewall rules in place for public IP addresses that are not in the approved public IP space:* \r\n";
        }
    }

    // The main JSON body
    public class SlackConfig
    {
        private string _username;
        private string _channel;
        private string _icon_url;
        private string _text;
        private List<attachment> _attachments;

        public string username
        {
            get => _username;
            set { _username = value; }
        }
        public string channel
        {
            get => _channel;
            set { _channel = value; }
        }
        public string icon_url
        {
            get => _icon_url;
            set { _icon_url = value; }
        }
        public string text
        {
            get => _text;
            set { _text = value; }
        }
        public List<attachment> attachments
        {
            get => _attachments;
            set { _attachments = value; }
        }
        public SlackConfig()
        {
            attachments = new List<attachment>();
            text = "The below message contains a list of _Azure PAAS SQL servers_ that contain firewall rules *NOT* in the approved public IP space. \r\n \r\n";
            username = "SqlFirewallBot";
            icon_url = "https://dotnetfoundation.org/img/dot_bot.png";
        }
    }
}
