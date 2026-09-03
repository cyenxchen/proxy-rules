# Proxy Rules

Personal, public rule sets shared by [Surge](https://nssurge.com/) and
[Mihomo](https://wiki.metacubex.one/). They supplement third-party upstream
lists without copying those lists. This repository intentionally publishes only
non-sensitive custom rules; private company, LAN, Tailscale, Ponte, and device
rules remain in local profiles.

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

Surge example:

```ini
RULE-SET,https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/IndependentIP.list,"🏠 Independent-IP","update-interval=86400"
RULE-SET,https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/Proxy.list,"👻 Proxy","update-interval=86400"
```

Mihomo uses the same raw files as classical text providers:

```yaml
rule-providers:
  customProxy:
    type: http
    behavior: classical
    format: text
    url: https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules/Proxy.list
    path: ./rule_provider/custom-Proxy.list
    interval: 86400

rules:
  - RULE-SET,customProxy,👻 Proxy
```

Each file contains rules for one profile-supplied policy because a Surge
`RULE-SET` applies one policy to every sub-rule. Keep these custom rule sets
before broader upstream rule sets. Surge evaluates rules from top to bottom and
uses the first matching policy.

Policy names are supplied by each client and may differ. For example,
`Apple.list` uses `🍎 Apple` in Surge and `🍎 AppleStore` in Mihomo. Direct
rules use the built-in `DIRECT` policy on both clients.

`extended-matching` is deliberately omitted from the example because the
initial rules were migrated from ordinary inline rules. Adding it would broaden
matching to TLS SNI and HTTP Host and could change behavior.

### Steam routing boundary

`Direct.list` sends Steam game downloads and the CM/CDN selection path through
the built-in `DIRECT` policy. The broader upstream Steam and SteamCN lists must
follow it and use the general proxy policy, so store, community, friends,
authentication, broadcasts, and game traffic are not made direct by default.

The maintained download list follows Valve's public
[`GetSteamPipeDomains`](https://api.steampowered.com/ISteamDirectory/GetSteamPipeDomains/v1/)
and content-server directory responses. `steamserver.net` is also direct because
the CM session location can affect the selected download cell. Third-party CDN
hosts use exact `DOMAIN` rules; `steamcontent.com` remains a suffix because
Valve publishes its cache fleet as `*.steamcontent.com`.

## Editing

- Put one Surge rule in each line.
- Do not include a policy name; the caller supplies the policy.
- Do not add `FINAL` or `pre-matching` to a rule set.
- Keep credentials, subscription URLs, private hostnames, and private network
  ranges out of this public repository.
- Run `python3 tests/validate_rules.py` before committing.
- Local Mihomo integration validation additionally requires PyYAML and uses
  `--mihomo-config /path/to/config.yaml`.

The validator logs each file's rule count, rejects unsupported syntax, unknown
files, and exact duplicates, and enforces conservative minimum counts to catch
truncation. With `--surge-config` or `--mihomo-config`, it also verifies every
published set's provider, policy, ordering, and completed inline-rule migration.
