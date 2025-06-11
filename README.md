# KQL-AC

Queries to search for sign-ons affected by Conditional Access policies matching Authentication Context for the Feide application.

## Querks



## Step-by-step

1) Check for available telemetry
   
```kql
SigninLogs
| where TimeGenerated >= ago(1h)
| where AppDisplayName == "Feide"
```
2) Identify sign-ons with Authentication Context

```kql
SigninLogs
| where TimeGenerated >= ago(3d)
| where AppDisplayName == "Feide"
| where AuthenticationContextClassReferences has "required"
```

8) Final query

```kql
let TimeFrame = 3d;
union 
(
    AADNonInteractiveUserSignInLogs
    | extend Source = "NonInteractive",
             DeviceDetailParsed = todynamic(DeviceDetail),
             ConditionalAccessPoliciesParsed = iff(isnull(ConditionalAccessPolicies), dynamic([]), todynamic(ConditionalAccessPolicies)),
             AuthContextParsed = iff(isnull(AuthenticationContextClassReferences), dynamic([]), todynamic(AuthenticationContextClassReferences))
),
(
    SigninLogs
    | extend Source = "Interactive",
             DeviceDetailParsed = DeviceDetail,
             ConditionalAccessPoliciesParsed = iff(isnull(ConditionalAccessPolicies), dynamic([]), todynamic(ConditionalAccessPolicies)),
             AuthContextParsed = iff(isnull(AuthenticationContextClassReferences), dynamic([]), todynamic(AuthenticationContextClassReferences))
)
| where TimeGenerated > ago(TimeFrame)
| where AppDisplayName == "Feide"
| mv-expand AuthContexts = AuthContextParsed
| where tostring(AuthContexts.detail) == "required"
| where tostring(AuthContexts.id) matches regex "c1[0-9]"
| extend RequiredACID = tostring(AuthContexts.id)
| summarize 
    RequiredACIDs = make_set(RequiredACID),
    ConditionalAccessPoliciesParsed = any(ConditionalAccessPoliciesParsed),
    DeviceDetailParsed = any(DeviceDetailParsed),
    ConditionalAccessStatus = any(ConditionalAccessStatus),
    ResultType = any(ResultType),
    ResultDescription = any(ResultDescription),
    IPAddress = any(IPAddress),
    AppDisplayName = any(AppDisplayName),
    Source = any(Source)
    by TimeGenerated, UserPrincipalName, CorrelationId, UserDisplayName
| mv-expand Policies = ConditionalAccessPoliciesParsed
| where Policies.displayName matches regex "(?i)AC - c1[0-9]"
| where Policies.result in ("success", "reportOnlySuccess", "failure", "reportOnlyFailure")
| extend ACID = tostring(RequiredACIDs[0])
| extend Device = tostring(DeviceDetailParsed.displayName),
         Compliant = tostring(DeviceDetailParsed.isCompliant),
         Managed = tostring(DeviceDetailParsed.isManaged)
| extend FirstName = iif(UserDisplayName contains ",", trim(" ", tostring(split(UserDisplayName, ",")[1])), split(UserDisplayName, " ")[0])
| extend FormattedTime = format_datetime(TimeGenerated, "M/d HH:mm")
| project FormattedTime, Source, FirstName, Device, Compliant, Managed, AppDisplayName, ACID, PolicyName = Policies.displayName, PolicyResult = Policies.result, ConditionalAccessStatus, ResultType, ResultDescription
| order by FormattedTime desc
```
