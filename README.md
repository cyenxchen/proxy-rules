# Proxy Rules

Personal, public [Surge](https://nssurge.com/) rule sets that supplement
third-party upstream lists. This repository intentionally publishes only
non-sensitive custom rules; private company, LAN, Tailscale, Ponte, and device
rules remain in the local Surge profile.

## Published rule sets

| Rule set | Policy supplied by the profile | Raw URL |
| --- | --- | --- |
| `Proxy.list` | `👻 Proxy` | `https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/Proxy.list` |

Example:

```ini
RULE-SET,https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/Proxy.list,"👻 Proxy","update-interval=86400"
```

Keep custom rule sets before broader upstream rule sets. Surge evaluates rules
from top to bottom and uses the first matching policy.

`extended-matching` is deliberately omitted from the example because the
initial rules were migrated from ordinary inline rules. Adding it would broaden
matching to TLS SNI and HTTP Host and could change behavior.

## Editing

- Put one Surge rule in each line.
- Do not include a policy name; the caller supplies the policy.
- Do not add `FINAL` or `pre-matching` to a rule set.
- Keep credentials, subscription URLs, private hostnames, and private network
  ranges out of this public repository.
- Run `python3 tests/validate_rules.py` before committing.

The validator logs each file's rule count, rejects unsupported syntax and exact
duplicates, and enforces a conservative minimum count to catch truncation.
