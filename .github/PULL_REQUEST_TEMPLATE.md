## Summary

<!-- What does this pull request add or change? Link any related issue, e.g. "Closes #12". -->

## Type of change

- [ ] New hunt
- [ ] Improvement to an existing hunt (logic, tuning or false positives)
- [ ] Documentation
- [ ] CI or tooling

## Hunt details (for new or changed hunts)

- **Folder:** `hunts/<YYYY>/<YYYY-MM-DD>-<slug>/`
- **Threat or CVE and primary source links:**
- **ATT&CK techniques:**
- **Platforms and tables:**

## Checklist

- [ ] Defensive content only: no exploit code, proofs of concept, payloads or exploitation steps.
- [ ] Indicators (if any) come from a cited public source and are linked. None are invented.
- [ ] No sensitive data (hostnames, usernames, IP addresses, tenant IDs, customer data).
- [ ] The README covers hypothesis, threat context, data sources, ATT&CK, tuning and false positives, and validation notes.
- [ ] KQL uses documented table and column names only.
- [ ] The Sigma rule has a new UUIDv4 `id`, the correct `status`, v2-style tags and `falsepositives`.
- [ ] `sigma check --fail-on-issues -x filename_length -x duplicate_filename hunts/` passes locally.
- [ ] The test conversion (`sigma convert -t kusto -p microsoft_xdr`) works.
- [ ] Validation notes say honestly what was and was not tested (isolated lab, benign simulation only).
- [ ] `CHANGELOG.md` and the README hunts table are updated.
- [ ] I agree that Sigma rules are licensed under DRL 1.1 and everything else under MIT.

## Testing notes

<!-- Where and how you tested: platform, data volume, benign simulation used, results. -->
