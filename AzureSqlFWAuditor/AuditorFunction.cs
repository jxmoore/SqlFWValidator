using System;
using NetTools;
using System.Net;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using System.Linq;
using System.Collections.Generic;
using System.Net.Http;
using AzureSqlFWAuditor.Slack;
using AzureSqlFWAuditor.Slack.Models;

namespace AzureSqlFWAuditor
{


    public static class AuditorFunction
    {

        // The current public ranges that we are allowing to access our SQL PAAS instances 
        // 0.0.0.0 - 0.0.0.0 being any azure address 
        // Any whitelist entries will be appended to this list.
        static readonly string[] ipRanges = {
                                      "0.0.0.0 - 0.0.0.0", "1.1.1.1 - 1.1.1.95", "96.0.10.1 - 96.0.10.5", "200.180.170.30 - 208.180.170.60", "5.17.22.0 - 5.17.22.255",
                                      "1.14.75.16 - 1.14.75.175", "92.16.238.144 - 92.16.238.159", "7.9.139.48 - 7.9.139.63", "16.72.66.128 - 16.72.66.143", "20.24.94.0 - 20.24.94.215"
                                    };

        [FunctionName("AuditorFunction")]
        public static void Run([TimerTrigger("0 0 15 * * *")] TimerInfo myTimer, TraceWriter log)  // 10:00AM eastern
        {
            log.Info($"{DateTime.Now} : Function starting...");
            int sqlOffenses = 0;
            string botToken = Environment.GetEnvironmentVariable("botToken");
            string ruleChange = Environment.GetEnvironmentVariable("UpdateRules");
            string whiteList = Environment.GetEnvironmentVariable("WhiteList");
            if (string.IsNullOrEmpty(botToken))
            {
                log.Error($"{DateTime.Now} : One or more of the required app settings is missing, check the Azure portal to verify all parameters.");
                return;
            }

            var slackClient = new SlackClient(new HttpClient(), botToken);
            var slackPost = new SlackPost { Channel = Environment.GetEnvironmentVariable("channel"), Text = "Azure SQL FW Auditor findings" };
            if (!bool.TryParse(ruleChange, out bool updateFwSetting))
            {
                updateFwSetting = false;
                log.Info($"{DateTime.Now} : Unable to parse 'UpdateRules' setting {ruleChange}. Defaulting to False");
            }
            else
                log.Info($"{DateTime.Now} : UpdateRules variable set to {updateFwSetting}");
            

            AzureCredentialsFactory credFactorty = new AzureCredentialsFactory();
            var msi = new MSILoginInformation(MSIResourceType.AppService);
            var msiCred = credFactorty.FromMSI(msi, AzureEnvironment.AzureGlobalCloud);
            var azureAuth = Azure.Configure()
                        .WithLogLevel(HttpLoggingDelegatingHandler.Level.BodyAndHeaders)
                        .Authenticate(msiCred);


            var approvedRanges = string.IsNullOrEmpty(whiteList) ? ipRanges.ToList() : ipRanges.Union(whiteList.Split(',')).ToList();
            log.Info($"{DateTime.Now} : Authenticated into tenant... Pulling subscriptions");
            var fields = new List<SlackField>();
            foreach (var sub in azureAuth.Subscriptions.List())
            {

                log.Verbose($"{DateTime.Now} : Logging into subscription : {sub.SubscriptionId.ToString()}");
                var azure = Azure.Configure()
                            .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                            .Authenticate(msiCred).WithSubscription(sub.SubscriptionId.ToString());

                // loop through the sql servers in the subscription 
                foreach (var server in azure.SqlServers.List())
                {
                    var outOfRangeRules = server.FirewallRules.List().Where(ruleDef => IsIpInRange(ruleDef.StartIPAddress, approvedRanges) == false || IsIpInRange(ruleDef.EndIPAddress, approvedRanges) == false);
                    // process all the rules that are deemed bad
                    foreach (var firewallRule in outOfRangeRules)
                    {
                        var field = new SlackField { Short = false, Title =" ", };

                        // The appsetting is set to true, so we try and delete the rule.
                        if (updateFwSetting)
                        {
                            try
                            {
                                firewallRule.Delete();
                                field.Value = $"Server - {server.Name}, Firewall Rule(s) : \r\n>{firewallRule.Name} : {firewallRule.StartIPAddress} - {firewallRule.EndIPAddress} *Deleted : YES*";
                            }
                            catch (Exception e)
                            {
                                field.Value = $"Server - {server.Name}, Firewall Rule(s) : \r\n>{firewallRule.Name} : {firewallRule.StartIPAddress} - {firewallRule.EndIPAddress} *Deleted : NO, encountered exception*";
                                log.Warning($"{DateTime.Now} : {e.Message}");
                            }

                        }
                        else
                        {
                            field.Value = $"{server.Name}, Firewall Rule(s) : \r\n>{firewallRule.Name} : {firewallRule.StartIPAddress} - {firewallRule.EndIPAddress} *Deleted : NO, deletion not enabled.*";
                            log.Info($"{DateTime.Now} : FW setting {updateFwSetting} firewall rule {firewallRule.Name} will be left to fester here");
                        }
                        
                        sqlOffenses++;

                    }

                    // Once its clean we add in missing ranges
                    AddInMissingIpRanges(log, server);
                }
            }

            if (fields.Any())
            {
                slackPost.Attachments = new List<SlackAttachment>() { new SlackAttachment { Fields = fields, Color = "ok", Title = " ", } };
                _ = slackClient.PostToSlackAsync(slackPost);
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
                    return true;

            }
            return false;
        }

        // This checks if a server is missing any of the current allowed firewall rules.
        // This does not include anything from the whitelist. 
        static int AddInMissingIpRanges(TraceWriter traceWriter, Microsoft.Azure.Management.Sql.Fluent.ISqlServer sqlServer)
        {
            traceWriter.Info($"{DateTime.Now} : Checking for missing rules on {sqlServer.Name}");
            List<string> currentFirewallRules = new List<string>();
            foreach (var fwRule in sqlServer.FirewallRules.List())
                currentFirewallRules.Add($"{fwRule.StartIPAddress} - {fwRule.EndIPAddress}");
            
            var missingRules = ipRanges.Except(currentFirewallRules);
            string addInMissingRules = Environment.GetEnvironmentVariable("AddInMissingRules");
            if (!bool.TryParse(addInMissingRules, out bool createNewRules))
                createNewRules = false;

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
                        traceWriter.Error($"{DateTime.Now} : Error creating ${missingFirewallRule} on ${sqlServer.Name} : {e.Message}");
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
                    return $"Some Public IP Space {DateTime.Now:yyyy-MM-dd}";
            }
        }
    }
}