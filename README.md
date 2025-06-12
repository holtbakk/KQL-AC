# Workbook

Exploring queries to search for sign-ins affected by Conditional Access policies matching Authentication Context for the Feide application.

## Requirements
* Log Analytics
* SigninLogs + AADNonInteractiveUserSignInLogs

## Quirks / Challenges

* Feide session lifetime.
* AuthenticationContext logging. Where is notApplicable?
* Fields not available in AADSignInEventsBeta in advanced hunting, the only (?) table containing both interactive and non-interactive sign-ins.

## Step-by-step

1) Check for all available telemetry.
   
```kql
let TimeFrame = 1h;
SigninLogs
| where TimeGenerated >= ago(TimeFrame)
| where AppDisplayName == "Feide"
```

2) Identify sign-ins with Authentication Context.

```kql
let TimeFrame = 3d;
SigninLogs
| where TimeGenerated >= ago(TimeFrame)
| where AppDisplayName == "Feide"
| where AuthenticationContextClassReferences has "required"
```

3) Obfuscate itentities and shorten date/time column. Expand to get Authentication Context and generic Conditional Access status.

```kql
let TimeFrame = 3d;
SigninLogs
| where TimeGenerated >= ago(TimeFrame)
| where AppDisplayName == "Feide"
| where AuthenticationContextClassReferences has "required"
| extend FirstName = iif(UserDisplayName contains ",", trim(" ", tostring(split(UserDisplayName, ",")[1])), split(UserDisplayName, " ")[0])
| extend FormattedTime = format_datetime(TimeGenerated, "M/d HH:mm")
| extend RequiredClassIds = array_concat(extract_all(@'"id":"([^"]+)"[^}]*"detail":"required"', AuthenticationContextClassReferences))
| mv-expand RequiredClassIds
| summarize RequiredClassIds = strcat_array(make_set(tostring(RequiredClassIds)), ", ") by TimeGenerated, UserPrincipalName, FirstName, FormattedTime, ConditionalAccessStatus
| order by TimeGenerated desc
| project FormattedTime, FirstName, RequiredClassIds, ConditionalAccessStatus
```

4) Expand to non-interactive sign-ins. Had to fix mismatch in DeviceDetail content type.
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
| where TimeGenerated >= ago(TimeFrame)
| where AppDisplayName == "Feide"
| where AuthenticationContextClassReferences has "required"
| extend FirstName = iif(UserDisplayName contains ",", trim(" ", tostring(split(UserDisplayName, ",")[1])), split(UserDisplayName, " ")[0])
| extend FormattedTime = format_datetime(TimeGenerated, "M/d HH:mm")
| extend RequiredClassIds = array_concat(extract_all(@'"id":"([^"]+)"[^}]*"detail":"required"', AuthenticationContextClassReferences))
| mv-expand RequiredClassIds
| summarize RequiredClassIds = strcat_array(make_set(tostring(RequiredClassIds)), ", ") by TimeGenerated, UserPrincipalName, FirstName, FormattedTime, ConditionalAccessStatus
| order by TimeGenerated desc
| project FormattedTime, FirstName, RequiredClassIds, ConditionalAccessStatus
```

5) Final query. AC matching C10-c19 and similar CAP name. Obfuscate identities.

```kql
let TimeFrame = 3d;
let AuthenticationContextRegex = "c1[0-9]";
let ConditionalAccessRegex = "(?i)AC - c1[0-9]";
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
| where tostring(AuthContexts.id) matches regex AuthenticationContextRegex
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
| where Policies.displayName matches regex ConditionalAccessRegex
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

## Referrals
https://learn.microsoft.com/en-us/graph/api/resources/authenticationcontext?view=graph-rest-beta

