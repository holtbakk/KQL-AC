# Workbook

Exploring queries to search for sign-ins affected by Conditional Access policies matching Authentication Context for the Feide application.

## Requirements
* Advanced hunting in Defender or Log Analytics
* SigninLogs + AADNonInteractiveUserSignInLogs

## Quirks / Challenges

* Feide session lifetime.
* AuthenticationContext logging. Where is notApplicable?
* Fields not available in AADSignInEventsBeta in advanced hunting, the only (?) table containing both interactive and non-interactive sign-ins.

## Step-by-step

1) Start by getting all available telemetry for investigation.
   
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

3) Expand to get Authentication Context and generic Conditional Access status. Obfuscate itentities and shorten date/time column for presentation.

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

4) Expand to include non-interactive sign-ins.
```kql
let TimeFrame = 3d;
union 
(
    SigninLogs | extend Source = "Interactive"
),
(
    AADNonInteractiveUserSignInLogs | extend Source = "NonInteractive"
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

5) Expand to check for device compliance and management. Fix for mismatch in DeviceDetail content type.
```kql
let TimeFrame = 3d;
union 
(
    SigninLogs | extend Source = "Interactive", DeviceDetailParsed = DeviceDetail
),
(
    AADNonInteractiveUserSignInLogs | extend Source = "NonInteractive", DeviceDetailParsed = todynamic(DeviceDetail)
)
| where TimeGenerated >= ago(TimeFrame)
| where AppDisplayName == "Feide"
| where AuthenticationContextClassReferences has "required"
| extend Device = tostring(DeviceDetailParsed.displayName), Compliant = tostring(DeviceDetailParsed.isCompliant), Managed = tostring(DeviceDetailParsed.isManaged)| extend FirstName = iif(UserDisplayName contains ",", trim(" ", tostring(split(UserDisplayName, ",")[1])), split(UserDisplayName, " ")[0])
| extend FormattedTime = format_datetime(TimeGenerated, "M/d HH:mm")
| extend RequiredClassIds = array_concat(extract_all(@'"id":"([^"]+)"[^}]*"detail":"required"', AuthenticationContextClassReferences))
| mv-expand RequiredClassIds
| summarize RequiredClassIds = strcat_array(make_set(tostring(RequiredClassIds)), ", ") by TimeGenerated, UserPrincipalName, FirstName, Device, Compliant, Managed, FormattedTime, ConditionalAccessStatus
| order by TimeGenerated desc
| project FormattedTime, FirstName, Device, Compliant, Managed, RequiredClassIds, ConditionalAccessStatus
```

6) Final query. Adding Domain for external users. Adding filter for Authentication Context matching C10-c19 and similar matching Conditional Access policy name. Displaying relevant results.

```kql
let TimeFrame = 3d;
let AuthenticationContextRegex = "c1[0-9]";
let ConditionalAccessRegex = "(?i)AC - c1[0-9]";
union 
(
    SigninLogs
    | extend Source = "Interactive",
             DeviceDetailParsed = DeviceDetail,
             ConditionalAccessPoliciesParsed = iff(isnull(ConditionalAccessPolicies), dynamic([]), todynamic(ConditionalAccessPolicies)),
             AuthContextParsed = iff(isnull(AuthenticationContextClassReferences), dynamic([]), todynamic(AuthenticationContextClassReferences))
),
(
    AADNonInteractiveUserSignInLogs
    | extend Source = "NonInteractive",
             DeviceDetailParsed = todynamic(DeviceDetail),
             ConditionalAccessPoliciesParsed = iff(isnull(ConditionalAccessPolicies), dynamic([]), todynamic(ConditionalAccessPolicies)),
             AuthContextParsed = iff(isnull(AuthenticationContextClassReferences), dynamic([]), todynamic(AuthenticationContextClassReferences))
)
| where TimeGenerated > ago(TimeFrame)
| where AppDisplayName == "Feide"
| mv-expand AuthContexts = AuthContextParsed
| where tostring(AuthContexts.detail) == "required"
| where tostring(AuthContexts.id) matches regex AuthenticationContextRegex
| extend RequiredACID = tostring(AuthContexts.id)
| summarize RequiredACIDs = make_set(RequiredACID), ConditionalAccessPoliciesParsed = any(ConditionalAccessPoliciesParsed), DeviceDetailParsed = any(DeviceDetailParsed), ConditionalAccessStatus = any(ConditionalAccessStatus), ResultType = any(ResultType), ResultDescription = any(ResultDescription), IPAddress = any(IPAddress), AppDisplayName = any(AppDisplayName), Source = any(Source) by TimeGenerated, UserPrincipalName, CorrelationId, UserDisplayName
| mv-expand Policies = ConditionalAccessPoliciesParsed
| where Policies.displayName matches regex ConditionalAccessRegex
| where Policies.result in ("success", "reportOnlySuccess", "failure", "reportOnlyFailure")
| extend ACID = tostring(RequiredACIDs[0])
| extend Device = tostring(DeviceDetailParsed.displayName), Compliant = tostring(DeviceDetailParsed.isCompliant), Managed = tostring(DeviceDetailParsed.isManaged)
| extend FirstName = iif(UserDisplayName contains ",", trim(" ", tostring(split(UserDisplayName, ",")[1])), split(UserDisplayName, " ")[0])
| extend Domain = iif(UserPrincipalName contains "@nmbu.no", "", tostring(split(UserPrincipalName, "@")[1]))
| extend FormattedTime = format_datetime(TimeGenerated, "M/d HH:mm")
| project FormattedTime, Source, FirstName, Domain, Device, Compliant, Managed, AppDisplayName, ACID, PolicyName = Policies.displayName, PolicyResult = Policies.result, ConditionalAccessStatus, ResultType, ResultDescription
| order by FormattedTime desc
```

## Referrals
* https://learn.microsoft.com/en-us/graph/api/resources/authenticationcontext?view=graph-rest-beta
* https://learn.microsoft.com/en-us/entra/identity-platform/developer-guide-conditional-access-authentication-context
