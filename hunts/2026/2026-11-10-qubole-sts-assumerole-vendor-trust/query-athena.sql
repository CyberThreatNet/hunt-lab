-- Qubole vendor-account AssumeRole (DRAFT FOR REVIEW, untested)
-- Hunt ID: 2026-11-10-qubole-sts-assumerole-vendor-trust
-- Replace the table name and JSON projection with your CloudTrail or CloudTrail Lake schema.
-- Review from 1 October 2026, as Wiz recommends.
-- Licence: MIT

-- Q1 / Q2 combined
SELECT
  eventtime,
  eventname,
  sourceipaddress,
  useridentity.accountid AS calling_account,
  useridentity.principalid AS calling_principal,
  useridentity.arn AS calling_arn,
  recipientaccountid,
  useragent,
  json_extract_scalar(requestparameters, '$.roleSessionName') AS role_session_name,
  json_extract_scalar(requestparameters, '$.roleArn') AS role_arn,
  CASE
    WHEN sourceipaddress LIKE '2001:41d0:70d:7800:%'
      OR sourceipaddress IN ('45.83.220.211', '57.129.54.120', '185.209.199.73', '89.37.63.175')
    THEN true ELSE false
  END AS indicator_ip,
  errorcode
FROM cloudtrail_logs
WHERE eventtime >= TIMESTAMP '2026-10-01 00:00:00'
  AND (
        useridentity.principalid LIKE '%AIDA3W7DIFLYOLTK63SFS%'
     OR (eventname = 'AssumeRole' AND useridentity.accountid = '805246085872')
  )
ORDER BY eventtime;

-- Q3 follow-on (management events only; GetObject needs S3 data events).
-- The quiam- ARN match is a starting filter, not a complete session join.
-- Still join follow-on events to the Q1/Q2 sessions in your own workspace.
SELECT
  eventtime,
  eventname,
  sourceipaddress,
  useridentity.accountid AS calling_account,
  useridentity.principalid AS calling_principal,
  useridentity.arn AS calling_arn,
  recipientaccountid,
  useragent,
  errorcode
FROM cloudtrail_logs
WHERE eventtime >= TIMESTAMP '2026-10-01 00:00:00'
  AND eventname IN (
    'GetSecretValue', 'ListSecrets',
    'GetParameter', 'GetParameters', 'GetParametersByPath', 'DescribeParameters',
    'GetFunctionConfiguration', 'ListFunctions',
    'ListBuckets', 'ListObjects', 'ListObjectsV2', 'HeadObject', 'GetObject',
    'GetCallerIdentity'
  )
  AND (
        useridentity.arn LIKE '%quiam-%'
     OR sourceipaddress IN ('45.83.220.211', '57.129.54.120', '185.209.199.73', '89.37.63.175')
     OR sourceipaddress LIKE '2001:41d0:70d:7800:%'
     OR useridentity.principalid LIKE '%AIDA3W7DIFLYOLTK63SFS%'
  )
ORDER BY eventtime;
