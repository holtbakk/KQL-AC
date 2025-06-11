# KQL-AC

## Intro

## Examples

```kql
SigninLogs
| where TimeGenerated >= ago(1h)
| where AppDisplayName == "Feide"
```

SigninLogs
| where TimeGenerated >= ago(3d)
| where AppDisplayName == "Feide"
| where AuthenticationContextClassReferences has "required"
