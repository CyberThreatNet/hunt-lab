# Contributing to Cyber-Threat.net Hunt Lab

Thanks for helping. Hunt Lab lives at <https://github.com/CyberThreatNet/hunt-lab> and feeds the Hunt Lab section of [Cyber-Threat.net](https://cyber-threat.net) (coming soon).

## Ground rules

- **Defensive content only.** We do not accept:
  - exploit code or working proofs of concept;
  - step-by-step exploitation instructions;
  - payloads, including "for testing".
- **No invented indicators.** IOCs (hashes, IP addresses, domains, URLs) are accepted only with a link to the public source that published them. Behaviour-based logic is preferred.
- **Cite primary sources.** Use the vendor advisory, NCSC, CISA KEV or CERT-EU first. Press reports may add context.
- **Test safely.** Validate with benign simulations in an isolated lab, on systems you own or are authorised to test.
- **No sensitive data.** Remove hostnames, usernames, IP addresses, tenant IDs and any customer data from examples and screenshots.
- Write in clear British English.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Request a hunt:** [open a new hunt request](https://github.com/CyberThreatNet/hunt-lab/issues/new?template=new-hunt-request.yml).
- **Report a false positive:** [open a false positive report](https://github.com/CyberThreatNet/hunt-lab/issues/new?template=false-positive-report.yml). Tell us what benign activity matched and the exclusion you used.
- **Improve a query or add a hunt:** open a pull request (see below).
- **Security issue in the repository or CI:** do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Adding a hunt

1. Fork <https://github.com/CyberThreatNet/hunt-lab> and create a branch.
2. Copy the template folder to the new hunt's location:

   ```bash
   cp -r templates/hunt-template hunts/<YYYY>/<YYYY-MM-DD>-<slug>
   ```

   - Use the publication date.
   - Make the slug a short, lower-case, hyphenated description of the behaviour, e.g. `php-web-server-spawning-shell`.

3. Fill in `README.md`:
   - hypothesis;
   - threat context with source links;
   - data sources and tables;
   - ATT&CK mapping;
   - tuning and false positives;
   - validation notes.
4. Write `query.kql`:
   - Use only documented table and column names. Check them in the [Defender XDR advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables).
   - Keep the header comment block.
5. Write `rule.yml` (Sigma):
   - Generate a new UUIDv4 for `id`.
   - Set `status: experimental` until the rule has been tested.
   - Use v2 tags (`attack.initial-access`, `attack.t1190`).
   - Fill in `falsepositives`.
6. Add `query.spl`, and other languages where the field mappings are clear.
7. Validate locally:

   ```bash
   python -m pip install sigma-cli==3.1.0 pysigma==1.5.1 \
     pysigma-backend-kusto==1.0.1 pysigma-backend-splunk==2.1.0 pysigma-backend-elasticsearch==2.1.1
   sigma check --fail-on-issues -x filename_length -x duplicate_filename hunts/
   sigma convert -t kusto -p microsoft_xdr hunts/<YYYY>/<YYYY-MM-DD>-<slug>/rule.yml
   ```

8. Add a line to `CHANGELOG.md` under "Unreleased" and to the Hunts table in `README.md`.
9. Open a pull request and complete the template. CI runs the same checks.

## Adapting someone else's rule

- **DRL 1.1 rules** (for example, from SigmaHQ):
  - keep the original `author`, and add yourself;
  - keep the link to the original rule in `references`.
- **Other licences:** check that the licence allows inclusion. If unsure, ask in the pull request.

## Licensing of contributions

By contributing, you agree that:
- your Sigma rules (`rule.yml`) are licensed under the [Detection Rule License 1.1](LICENSE-DRL);
- everything else is licensed under the [MIT Licence](LICENSE).

## Review

A maintainer will review for:
- safety;
- accuracy against the cited sources;
- schema correctness;
- tuning guidance.

Hunts are published on Cyber-Threat.net only after they have been tested.
