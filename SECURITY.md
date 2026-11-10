# Security policy

Only the latest release receives security fixes.

Report vulnerabilities privately through this repository's
[Security Advisories page](https://github.com/louisdibiasi/rustwisp/security/advisories/new).
Include the affected version, steps to reproduce the issue and its impact.
The maintainer will acknowledge the report, investigate it and coordinate a fix
and disclosure with you. Please keep the details private while a fix is prepared.

Known limits:

- Twisp runs commands with the server account's privileges, working directory
  and environment. It is not a sandbox; a login grants shell access.
- `proxy-send-hostnames = on` delegates name resolution and address enforcement
  to the upstream proxy. Use it only with a proxy that enforces its own egress rules.
- Mixed password schemes or costs can reveal account types through login timing.
  Use the same hash scheme and cost for every account.
