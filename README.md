# Proxy Rules

Personal, public [Surge](https://nssurge.com/) rule sets that supplement
third-party upstream lists. This repository intentionally publishes only
non-sensitive custom rules; private company, LAN, Tailscale, Ponte, and device
rules remain in the local Surge profile.

## Published rule sets

| Rule set | Policy supplied by the profile | Raw URL |
| --- | --- | --- |
| `Apple.list` | `🍎 Apple` | `https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/Apple.list` |
| `Direct.list` | `DIRECT` | `https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/Direct.list` |
| `IndependentIP.list` | `🏠 Independent-IP` | `https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/IndependentIP.list` |
| `JP.list` | `🇯🇵 JP` | `https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/JP.list` |
| `PlayStation.list` | `🎮 PlayStation` | `https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/PlayStation.list` |
| `Proxy.list` | `👻 Proxy` | `https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/Proxy.list` |
| `SGP.list` | `🇸🇬 SGP` | `https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/SGP.list` |
| `UK.list` | `🇬🇧 UK` | `https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/UK.list` |
| `US.list` | `🇺🇸 US` | `https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/US.list` |

Example:

```ini
RULE-SET,https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/IndependentIP.list,"🏠 Independent-IP","update-interval=86400"
RULE-SET,https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/Proxy.list,"👻 Proxy","update-interval=86400"
```

Each file contains rules for one profile-supplied policy because a Surge
`RULE-SET` applies one policy to every sub-rule. Keep these custom rule sets
before broader upstream rule sets. Surge evaluates rules from top to bottom and
uses the first matching policy.

The repository stores only custom overlays; it does not mirror entire upstream
lists. Private company, LAN, Tailscale, Ponte, and device-specific rules remain
inline in the local profile.

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

The validator logs each file's rule count, rejects unsupported syntax, unknown
files, and exact duplicates, and enforces conservative minimum counts to catch
truncation. With `--surge-config`, it also verifies every published set's policy,
ordering, and completed inline-rule migration.
