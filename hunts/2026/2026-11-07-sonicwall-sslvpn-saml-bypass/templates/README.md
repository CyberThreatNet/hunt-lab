# TEMPLATE, NOT DEPLOYABLE

These files show the auth-method check (Hunt 2) but rely on a field we could not validate. SonicWall documents event 1080 ("SSL VPN zone remote user login allowed") with user, source and session fields. We found no SonicWall or Microsoft documentation of a field that records whether the login used SAML, local, LDAP or RADIUS.

- `rule-sslvpn-nonsaml-login.yml.template`: Sigma, status unsupported. The `.template` suffix keeps it out of CI conversion.
- `query-auth-method.kql.template`: KQL Q2.

The draft had a break-glass exclusion. We removed it: a default allow-list can hide the exact account an attacker uses. Add exclusions only after review, and alert on them separately.
