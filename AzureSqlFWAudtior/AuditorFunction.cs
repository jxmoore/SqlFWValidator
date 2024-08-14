using System;
using AzureSqlFWAuditor.Slack.Models;
using AzureSqlFWAuditor.Slack;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using NetTools;
using System.Net;

namespace AzureSqlFWAudtior;

public static class AuditorFunction
{

    static readonly string[] ipRanges =
    {
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

        if (!bool.TryParse(ruleChange, out bool updateFwSetting))
            log.Info($"{DateTime.Now} : Unable to parse 'UpdateRules' setting {ruleChange}. Defaulting to False");
        else
            log.Info($"{DateTime.Now} : UpdateRules variable set to {updateFwSetting}");

        if (string.IsNullOrEmpty(botToken))
        {
            log.Error($"{DateTime.Now} : Ensure the bot token is set in the appsettings.");
            return;
        }

        var slackClient = new SlackClient(new HttpClient(), botToken);
        var slackPost = new SlackPost { Channel = Environment.GetEnvironmentVariable("channel"), Text = "Azure SQL FW Auditor findings" };

        var approvedRanges = string.IsNullOrEmpty(whiteList) ? [.. ipRanges] : ipRanges.Union(whiteList.Split(',')).ToList();

        var msiCred = new AzureCredentialsFactory().FromMSI(new MSILoginInformation(MSIResourceType.AppService), AzureEnvironment.AzureGlobalCloud);
        var azureAuth = Azure.Configure()
                    .WithLogLevel(HttpLoggingDelegatingHandler.Level.BodyAndHeaders)
                    .Authenticate(msiCred);

        log.Info($"{DateTime.Now} : Authenticated into tenant... Pulling subscriptions");
        var fields = new List<SlackField>();
        foreach (var sub in azureAuth.Subscriptions.List())
        {

            log.Verbose($"{DateTime.Now} : Logging into subscription : {sub.SubscriptionId}");
            var azure = Azure.Configure()
                        .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                        .Authenticate(msiCred).WithSubscription(sub.SubscriptionId);

            // loop through the sql servers in the subscription 
            foreach (var server in azure.SqlServers.List())
            {
                var outOfRangeRules = server.FirewallRules.List()
                    .Where(ruleDef => IsIpInRange(ruleDef.StartIPAddress, approvedRanges) == false || IsIpInRange(ruleDef.EndIPAddress, approvedRanges) == false);
                
                // process all the rules that are deemed bad
                foreach (var firewallRule in outOfRangeRules)
                {
                    sqlOffenses++;
                    var field = new SlackField
                    {
                        Short = false,
                        Title = " ",
                        Value = $"{server.Name}, Firewall Rule(s) : \r\n>{firewallRule.Name} : {firewallRule.StartIPAddress} - {firewallRule.EndIPAddress} *Deleted : NO, deletion not enabled.*"
                    };

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

                    fields.Add(field);
                }

                // Once its clean we add in missing ranges
                AddInMissingIpRanges(log, server);
            }
        }

        if (fields is null)
            return;

            slackPost.Attachments = [new SlackAttachment { Fields = fields, Color = "ok", Title = " ", }];
            _ = slackClient.PostToSlackAsync(slackPost);
    }

    /// <summary>
    /// Small helper to check to see if a list of ip's is in a given range
    /// </summary>
    /// <param name="ipAddress"></param>
    /// <param name="allowedRanges"></param>
    /// <returns></returns>
    static bool IsIpInRange(string ipAddress, List<string> allowedRanges)
    {
        var ip = IPAddress.Parse(ipAddress);
        foreach (var allowedRange in allowedRanges)
            if (IPAddressRange.Parse(allowedRange).Contains(ip))
                return true;

        return false;
    }

    /// <summary>
    /// Checks if a server is missing any of the current allowed firewall rules.
    /// </summary>
    /// <param name="traceWriter">The Logger</param>
    /// <param name="sqlServer">The Sql server instance to check against</param>
    /// <returns>an int, currently not indicitave of anything</returns>
    static int AddInMissingIpRanges(TraceWriter traceWriter, Microsoft.Azure.Management.Sql.Fluent.ISqlServer sqlServer)
    {
        traceWriter.Info($"{DateTime.Now} : Checking for missing rules on {sqlServer.Name}");
        List<string> currentFirewallRules = sqlServer.FirewallRules.List().Select(x => $"{x.StartIPAddress} - {x.EndIPAddress}").ToList();
        var missingRules = ipRanges.Except(currentFirewallRules);

        bool createNewRules = bool.TryParse(Environment.GetEnvironmentVariable("AddInMissingRules"), out bool addInMissingRules) && addInMissingRules;
        if (!createNewRules)
            return 0; 

        foreach (var missingFirewallRule in missingRules.ToList())
        {
            try
            {
                var ruleName = RangeToRuleName(missingFirewallRule);
                traceWriter.Info($"{DateTime.Now} : Creating {ruleName} on {sqlServer.Name} - {missingFirewallRule}");
                sqlServer.FirewallRules.Define(ruleName).
                    WithIPAddressRange(missingFirewallRule.Split('-')[0].Trim(), missingFirewallRule.Split('-')[1].Trim()).Create();
            }
            catch (Exception e)
            {
                traceWriter.Error($"{DateTime.Now} : Error creating ${missingFirewallRule} on ${sqlServer.Name} : {e.Message}");
            }
        }

        return 0;
    }

    /// <summary>
    /// Just maps a range to a friendly string
    /// </summary>
    /// <param name="range">The given range to map to a user friendly string</param>
    /// <returns>the string</returns>
    static string RangeToRuleName(string range) => range switch
    {
        "0.0.0.0 - 0.0.0.0" => "Allow All Azure Traffic",
        "1.1.1.1 - 1.1.1.95" => "Teddys house",
        "96.0.10.1 - 96.0.10.5" => "Stadium traffic",
        "200.180.170.30 - 208.180.170.60" => "The roxy",
        "5.17.22.0 - 5.17.22.255" => "Pickle stand",
        "1.14.75.16 - 1.14.75.175" => "Costco",
        "92.16.238.144 - 92.16.238.159" => "Starbucks",
        "7.9.139.48 - 7.9.139.63" => "Satelite office",
        "16.72.66.128 - 16.72.66.143" => "Teddys moms",
        _ => $"Some Public IP Space {DateTime.Now:yyyy-MM-dd}",// Datetime should guarantee that the rule name is unique on the PAAS instance
    };
    
}
