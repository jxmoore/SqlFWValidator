## Azure Sql PAAS FW Validator

This is an Azure function that goes through all of the Azure SQL PAAS instances and audits the SQL FW rules. The `allowed` rules are within the main SqlValidator.CS and can be adjusted via enviroment variables (see below). It collects all offending rules that are found for reporting and if set to do so, can remove them automatically. Once an instance has been audited any rules in the `allowed` list that are missing from the PAAS instance will be added. 

At the end of the run a message with the details of the run are posted to the specified slack channel, most output is also captured in the standard STDOUT using the standard `TraceWriter`.


The enviroment variables drive some of this :
```C#
slackMsg.channel = Environment.GetEnvironmentVariable("channel"); // The channel we are posting too 
string slackHook = Environment.GetEnvironmentVariable("hook"); // the web hook we will use to post the message
string ruleChange = Environment.GetEnvironmentVariable("UpdateRules"); // a bool, are we updating the rules or just reporting on them
string whiteList = Environment.GetEnvironmentVariable("WhiteList"); // any additional ranges we want to add without having to deploy code changes 
```


The function does not use standard credentials it uses an MSI, which should be given the `SQL SECURITY MANAGER` role at the subscription level. 
