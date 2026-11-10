# Audit stale third-party trust for the Qubole AWS account

These commands are a defensive inventory, based on Wiz's 9 November 2026 advice to list every IAM role that trusts an external account, and to remove trust you no longer use. They are our wording, not a vendor script. Review every hit before you change or delete a role. Run them in each account that may hold an integration role, from a workstation that already has the access you need. Do not paste secrets into the command line.

## AWS CLI: roles whose trust policy mentions 805246085872

```bash
aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument), '805246085872')].[RoleName,Arn,RoleLastUsed.LastUsedDate]" --output table
```

For each role name that is returned, inspect the trust policy and when the role was last used:

```bash
aws iam get-role --role-name "$ROLE_NAME" --query "Role.{RoleName:RoleName,Arn:Arn,LastUsed:RoleLastUsed,Trust:AssumeRolePolicyDocument}" --output json
aws iam list-attached-role-policies --role-name "$ROLE_NAME"
aws iam list-role-policies --role-name "$ROLE_NAME"
```

A missing last-used date, or no use during October 2026, is a reason to look harder. It is not an automatic deletion order. If you no longer use Qubole, remove the vendor account from the trust policy or delete the unused role after change control. If you still use it, Wiz advises replacing an account-root principal with the specific vendor identity where the vendor supports that, and adding an `aws:SourceIp` or `aws:SourceVpce` condition. Wiz says a source IP condition alone would have blocked every role assumption it observed.

## IAM Access Analyzer

If an external-access analyser is already enabled in the account or the organisation:

```bash
aws accessanalyzer list-analyzers
aws accessanalyzer list-findings --analyzer-arn "$ANALYZER_ARN" --filter '{"principal.AWS":{"eq":["805246085872"]}}'
```

You can also list findings for any external AWS account, then review unused or over-broad vendor roles, not only Qubole:

```bash
aws accessanalyzer list-findings --analyzer-arn "$ANALYZER_ARN" --filter '{"resourceType":{"eq":["AWS::IAM::Role"]}}'
```

Do not create or change analysers, policies or roles from this note alone. Use your normal change process.

## After a confirmed assumption

Wiz says: rotate every secret, parameter and Lambda environment variable the role could read, and revoke active sessions for the role. Rotating a credential does not end temporary sessions that have already been issued.
