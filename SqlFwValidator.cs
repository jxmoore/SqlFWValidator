using System;
using NetTools;
using System.Net;
using System.Text;
using Newtonsoft.Json;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using System.Collections.Specialized;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using System.Linq;
using System.Collections.Generic;

namespace SQLIpRange
{


    public static class SQLFWValidator 
    {

        // The current public ranges that we are allowing to access our SQL PAAS instances 
        // 0.0.0.0 - 0.0.0.0 being any azure address 
        // Any whitelist entries will be appended to this list.
        static readonly string[] ipRanges = {
                                      "0.0.0.0 - 0.0.0.0", "1.1.1.1 - 1.1.1.95", "96.0.10.1 - 96.0.10.5", "200.180.170.30 - 208.180.170.60", "5.17.22.0 - 5.17.22.255",
                                      "1.14.75.16 - 1.14.75.175", "92.16.238.144 - 92.16.238.159", "7.9.139.48 - 7.9.139.63", "16.72.66.128 - 16.72.66.143", "20.24.94.0 - 20.24.94.215"
                                    };

        [FunctionName("SQLFWValidator")]
        public static void Run([TimerTrigger("0 0 15 * * *")]TimerInfo myTimer, TraceWriter log)  // 10:00AM eastern
        {
            log.Info($"{DateTime.Now} : Function starting...");
            field slackField = new field();
            attachment slackBody = new attachment();
            SlackConfig slackMsg = new SlackConfig();
            int sqlOffenses = 0;

            // env variables = Azre app settings
            slackMsg.channel = Environment.GetEnvironmentVariable("channel"); // The channel we are posting too 
            string slackHook = Environment.GetEnvironmentVariable("hook"); // the web hook we will use to post the message
            string ruleChange = Environment.GetEnvironmentVariable("UpdateRules"); // a bool, are we updating the rules or just reporting on them
            string whiteList = Environment.GetEnvironmentVariable("WhiteList"); // any additional ranges we want to add without having to deploy code changes 
            
            // No hook will result in the post failing, no channel will result in it going to the default channel.
            if (string.IsNullOrEmpty(slackHook) || string.IsNullOrEmpty(slackMsg.channel))
            {
                log.Error($"{DateTime.Now} : One or more of the required app settings is missing, check the Azure portal to verify all parameters.");
                return;
            }
            
            // Determine validity of ruleChange
            if (!bool.TryParse(ruleChange, out bool updateFwSetting))
            {
                updateFwSetting = false;
                log.Info($"{DateTime.Now} : Unable to parse 'UpdateRules' setting {ruleChange}. Defaulting to False");
            }
            else
            {
                log.Info($"{DateTime.Now} : UpdateRules variable set to {updateFwSetting}");
            }

            // Create cred from msi endpoint (ENV variable on localhost) and auth
            AzureCredentialsFactory credFactorty = new AzureCredentialsFactory();
            var msi = new MSILoginInformation(MSIResourceType.AppService);            
            var msiCred = credFactorty.FromMSI(msi, AzureEnvironment.AzureGlobalCloud);            
            var azureAuth = Azure.Configure()
                        .WithLogLevel(HttpLoggingDelegatingHandler.Level.BodyAndHeaders)
                        .Authenticate(msiCred);

          
            Uri hookUri = new Uri(slackHook);
            var approvedRanges = string.IsNullOrEmpty(whiteList) ? ipRanges.ToList() : ipRanges.Union(whiteList.Split(',')).ToList();
            log.Info($"{DateTime.Now} : Authenticated into tenant... Pulling subscriptions");

            // Looping through subscriptions, re-authing into each one
            foreach (var sub in azureAuth.Subscriptions.List())
            {

                log.Verbose($"{DateTime.Now} : Logging into subscription : {sub.SubscriptionId.ToString()}");
                var azure = Azure.Configure()
                            .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                            .Authenticate(msiCred).WithSubscription(sub.SubscriptionId.ToString());
  
                // loop through the sql servers in the subscription 
                foreach (var server in azure.SqlServers.List())
                {

                    log.Verbose($"{DateTime.Now} : Processing {server.Name} in resource group {server.ResourceGroupName}");
                    var outOfRangeRules = server.FirewallRules.List().Where(ruleDef => 
                        IsIpInRange(ruleDef.StartIPAddress, approvedRanges) == false || IsIpInRange(ruleDef.EndIPAddress, approvedRanges) == false).ToList();

                    // process all the rules that are deemed bad
                    foreach (var firewallRule in outOfRangeRules)
                    {
                        sqlOffenses++;
                        slackBody.text += slackBody.text.Contains(server.Name) ?
                            $">{firewallRule.Name} : {firewallRule.StartIPAddress} - {firewallRule.EndIPAddress} *Deleted :* " :
                            $"\r\n *Server - {server.Name}, Firewall Rule(s) :* \r\n>{firewallRule.Name} : {firewallRule.StartIPAddress} - {firewallRule.EndIPAddress} *Deleted :*";

                        log.Warning($"{DateTime.Now} : Found bad rule on {server.Name}, rule : {firewallRule.Name} : {firewallRule.StartIPAddress} - {firewallRule.EndIPAddress}");

                        // The appsetting is set to true, so we try and delete the rule.
                        if (updateFwSetting)
                        {
                            try
                            {
                                firewallRule.Delete();
                                slackBody.text += $"*Yes* \r\n";
                                log.Warning($"{DateTime.Now} : {firewallRule.Name} removed on server {server.Name} in resource group {server.ResourceGroupName}");
                            }
                            catch (Exception errorException)
                            {

                                // catch all is dirty need to revisit when i have time
                                slackBody.text += $"*No encountered exception.* \r\n";
                                log.Warning($"{DateTime.Now} : Failed to delete {firewallRule.Name} on server {server.Name} in resource group {server.ResourceGroupName}");
                                log.Warning($"{DateTime.Now} : {errorException.ToString()}");
                            }

                        }
                        else
                        {

                            // The variable is set to false so the rule stays
                            slackBody.text += $"*Not Enabled.* \r\n";
                            log.Info($"{DateTime.Now} : FW setting {updateFwSetting} firewall rule {firewallRule.Name} will be left to fester here");
                        }
                    }
                    
                    // Once its clean we add in missing ranges
                    AddInMissingIpRanges(log, server);
                }
            }

            log.Info($"{DateTime.Now} : Total number of out of range rules: {sqlOffenses}.");
            // Serialize and post to slack
            slackField.value = "Urgent";
            if (slackBody.text.Contains("*Server - ") || slackBody.text.Contains("Deleted :"))
            {
                slackBody.fields.Add(slackField);
                slackMsg.attachments.Add(slackBody);
                string payloadJson = JsonConvert.SerializeObject(slackMsg);
                log.Info($"{DateTime.Now} : Posting to slack...");
                try
                {
                    string postresponse = PostToSlack(payloadJson, hookUri);
                    log.Info($"{DateTime.Now} : {postresponse}");
                }
                catch (Exception errorexception)
                {
                    log.Error($"{DateTime.Now} : {errorexception.ToString()}");
                    return;
                }  
            }

        }

        // Checks if a supplied IP is in the cidr range of one of the approved ranges
        static bool IsIpInRange(string ipAddress, List<string> allowedRanges)
        {
            var ip = IPAddress.Parse(ipAddress);
            foreach (var ipRange in allowedRanges)
            {
                var inRange = IPAddressRange.Parse(ipRange);
                if (inRange.Contains(ip))
                {

                    // The Ip address provided is within range.
                    return true;
                }

            }
            return false;
        }

        // This checks if a server is missing any of the current allowed firewall rules.
        // This does not include anything from the whitelist. 
        static int AddInMissingIpRanges(TraceWriter traceWriter, Microsoft.Azure.Management.Sql.Fluent.ISqlServer sqlServer)
        {
    
            // This is slightly hokey - The firewall rules in Azure are returned as two strings,
            // one for the start IP and one for the end. This is why its fanagled into a new list<string>.
            traceWriter.Info($"{DateTime.Now} : Checking for missing rules on {sqlServer.Name}");
            List<string> currentFirewallRules = new List<string>();
            foreach (var fwRule in sqlServer.FirewallRules.List())
            {
                currentFirewallRules.Add($"{fwRule.StartIPAddress} - {fwRule.EndIPAddress}");

            }

            var missingRules = ipRanges.Except(currentFirewallRules);
            string addInMissingRules = Environment.GetEnvironmentVariable("AddInMissingRules");
            if (!bool.TryParse(addInMissingRules, out bool createNewRules))
            {
                createNewRules = false;
            }

            if (createNewRules == true)
            {
                foreach (var missingFirewallRule in missingRules.ToList())
                {
                    var ruleName = RangeToRuleName(missingFirewallRule);
                    traceWriter.Info($"{DateTime.Now} : {sqlServer.Name} does not contain {ruleName} - {missingFirewallRule}");

                    try
                    {
                        sqlServer.FirewallRules.Define(ruleName).
                            WithIPAddressRange(missingFirewallRule.Split('-')[0].Trim(), missingFirewallRule.Split('-')[1].Trim()).Create();
                    }
                    catch (Exception e)
                    {
                        traceWriter.Error($"{DateTime.Now} : Error creating ${missingFirewallRule} on ${sqlServer.Name} :");
                        traceWriter.Error($"{DateTime.Now} : {e.ToString()}");
                    }
                }
            }

            return 0;
        }

        // super quick case statement to give rules a name
        static string RangeToRuleName(string range)
        {

            switch (range)
            {
                case "0.0.0.0 - 0.0.0.0":
                    return "Allow All Azure Traffic";
                case "1.1.1.1 - 1.1.1.95":
                    return "Teddys house";
                case "96.0.10.1 - 96.0.10.5":
                    return "Stadium traffic";
                case "200.180.170.30 - 208.180.170.60":
                    return "The roxy";
                case "5.17.22.0 - 5.17.22.255":
                    return "Pickle stand";
                case "1.14.75.16 - 1.14.75.175":
                    return "Costco";
                case "92.16.238.144 - 92.16.238.159":
                    return "Starbucks";
                case "7.9.139.48 - 7.9.139.63":
                    return "Satelite office";
                case "16.72.66.128 - 16.72.66.143":
                    return "Teddys moms";
                default:

                    // Datetime should guarantee that the rule name is unique on the PAAS instance
                    return $"Some Public IP Space {DateTime.Now.ToString("yyyy-MM-dd")}";
            }
        }
        // Simple method of post, doing this gets around using containing try/catch or vice versa
        static string PostToSlack(string json, Uri uri)
        {

            // Need to move to HTTPClient
            using (WebClient client = new WebClient())
            {
                NameValueCollection data = new NameValueCollection();
                data["payload"] = json;
                var response = client.UploadValues(uri, "POST", data);
                string responseText = new UTF8Encoding().GetString(response);
                return responseText;
            }
        }
    }
}