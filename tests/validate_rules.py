#!/usr/bin/env python3
"""Validate published Surge rule sets and the local integration config."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from pathlib import Path


# Keep the validator deliberately narrow: these are the rule types this
# repository publishes. Unsupported types fail loudly instead of being skipped
# silently by Surge.
ALLOWED_TYPES = {
    "DOMAIN",
    "DOMAIN-KEYWORD",
    "DOMAIN-SUFFIX",
    "IP-ASN",
    "IP-CIDR",
    "IP-CIDR6",
    "PROCESS-NAME",
    "URL-REGEX",
    "USER-AGENT",
}
ALLOWED_OPTIONS = {"extended-matching", "no-resolve"}
# Each file is grouped by the single policy supplied by rule.dconf. Keep the
# migration-size floors so an accidental truncation cannot be published.
PUBLISHED_RULE_SETS = {
    "Apple.list": ("🍎 Apple", 5),
    "Direct.list": ("DIRECT", 19),
    "IndependentIP.list": ("🏠 Independent-IP", 18),
    "JP.list": ("🇯🇵 JP", 3),
    "PlayStation.list": ("🎮 PlayStation", 6),
    "Proxy.list": ("👻 Proxy", 377),
    "SGP.list": ("🇸🇬 SGP", 15),
    "UK.list": ("🇬🇧 UK", 2),
    "US.list": ("🇺🇸 US", 8),
}
MINIMUM_RULE_COUNTS = {
    name: minimum for name, (_, minimum) in PUBLISHED_RULE_SETS.items()
}
RAW_BASE_URL = (
    "https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules"
)
MIHOMO_RULE_PROVIDERS = {
    "Apple.list": ("customApple", "🍎 AppleStore"),
    "Direct.list": ("customDirect", "DIRECT"),
    "IndependentIP.list": ("customIndependentIP", "🏠 Independent-IP"),
    "JP.list": ("customJP", "🇯🇵 JP"),
    "PlayStation.list": ("customPlayStation", "🎮 PlayStation"),
    "Proxy.list": ("customProxy", "👻 Proxy"),
    "SGP.list": ("customSGP", "🇸🇬 SGP"),
    "UK.list": ("customUK", "🇬🇧 UK"),
    "US.list": ("customUS", "🇺🇸 US"),
}
MIHOMO_GROUPS_WITH_UK = {
    "👻 Proxy",
    "Ⓜ️ Microsoft",
    "🍎 Apple",
    "🍎 AppleStore",
    "🌐 Google",
    "📺 Netflix",
    "📺 BiliBili",
    "🎮 PlayStation",
}
# Steam download traffic and the control plane that selects its CDN must use
# DIRECT. Exact third-party hosts stay narrow so unrelated services under the
# same provider domains continue through the upstream Steam proxy rules.
STEAM_DIRECT_RULES = {
    ("DOMAIN-SUFFIX", "steamserver.net"),
    ("DOMAIN", "api.steampowered.com"),
    ("DOMAIN", "cs.steampowered.com"),
    ("DOMAIN-SUFFIX", "steamcontent.com"),
    ("DOMAIN", "cdn-ali.content.steamchina.com"),
    ("DOMAIN", "cdn-qc.content.steamchina.com"),
    ("DOMAIN", "cdn-ws.content.steamchina.com"),
    ("DOMAIN", "dl.steam.clngaa.com"),
    ("DOMAIN", "edge.steam-dns.top.comcast.net"),
    ("DOMAIN", "lv.queniujq.cn"),
    ("DOMAIN", "st.dl.bscstorage.net"),
    ("DOMAIN", "st.dl.eccdnx.com"),
    ("DOMAIN", "steam.cdn.on.net"),
    ("DOMAIN", "steampipe-kr.akamaized.net"),
    ("DOMAIN", "steampipe-partner.akamaized.net"),
    ("DOMAIN", "steampipe-sc.akamaized.net"),
    ("DOMAIN", "steampipe-tr.akamaized.net"),
    ("DOMAIN", "steampipe.akamaized.net"),
    ("DOMAIN", "xz.pphimalayanrt.com"),
}
STALE_DIRECT_RULES = {
    ("DOMAIN-SUFFIX", "dl.steam.ksyna.com"),
    ("DOMAIN-SUFFIX", "st.dl.pinyuncloud.com"),
    ("DOMAIN-SUFFIX", "steampipe.steamcontent.tnkjmec.com"),
    ("DOMAIN-SUFFIX", "steampowered.com.8686c.com"),
    ("DOMAIN-SUFFIX", "steamstatic.com.8686c.com"),
    ("DOMAIN-SUFFIX", "taobao.taobao"),
}
NON_DOWNLOAD_STEAM_RULES = {
    ("DOMAIN", "steambroadcast-test.akamaized.net"),
    ("DOMAIN", "steambroadcast.akamaized.net"),
    ("DOMAIN", "steambroadcastchat.akamaized.net"),
    ("DOMAIN", "broadcast.st.dl.eccdnx.com"),
}
APPLE_UMBRELLA = "/rule/Surge/Apple/Apple.list"
APPLE_INCLUDED_SUBRULES = {
    "/rule/Surge/AppleFirmware/AppleFirmware.list",
    "/rule/Surge/AppleHardware/AppleHardware.list",
    "/rule/Surge/AppleMail/AppleMail.list",
    "/rule/Surge/AppleMedia/AppleMedia.list",
    "/rule/Surge/AppleMusic/AppleMusic.list",
    "/rule/Surge/AppleNews/AppleNews.list",
    "/rule/Surge/AppleProxy/AppleProxy.list",
    "/rule/Surge/AppleTV/AppleTV.list",
}


def log(message: str) -> None:
    """Emit a stable prefix so local and GitHub Actions logs are searchable."""
    print(f"[validate] {message}")


def parse_rule(raw_line: str, location: str) -> tuple[list[str] | None, str | None]:
    """Parse one rule line, returning None for comments and blank lines."""
    line = raw_line.strip()
    if not line or line.startswith(("#", ";", "//")):
        return None, None

    try:
        fields = [field.strip() for field in next(csv.reader([line]))]
    except csv.Error as exc:
        return None, f"{location}: invalid CSV syntax: {exc}"

    if len(fields) < 2:
        return None, f"{location}: a rule needs at least TYPE and VALUE"
    if fields[0] not in ALLOWED_TYPES:
        return None, f"{location}: unsupported rule type {fields[0]!r}"
    if not fields[1]:
        return None, f"{location}: empty rule value"
    if "pre-matching" in fields[2:]:
        return None, f"{location}: pre-matching is not valid inside a rule set"

    unknown_options = set(fields[2:]) - ALLOWED_OPTIONS
    if unknown_options:
        return None, f"{location}: unexpected policy or option {sorted(unknown_options)!r}"

    if fields[0] in {"IP-CIDR", "IP-CIDR6"}:
        try:
            network = ipaddress.ip_network(fields[1], strict=False)
        except ValueError as exc:
            return None, f"{location}: invalid network: {exc}"
        expected_version = 6 if fields[0] == "IP-CIDR6" else 4
        if network.version != expected_version:
            return None, f"{location}: address family does not match {fields[0]}"

    return fields, None


def validate_rule_file(path: Path) -> list[str]:
    """Validate syntax, duplicates, and a conservative minimum rule count."""
    errors: list[str] = []
    seen: dict[tuple[str, ...], int] = {}
    count = 0

    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        fields, error = parse_rule(raw_line, f"{path}:{line_number}")
        if error:
            errors.append(error)
            continue
        if fields is None:
            continue

        key = tuple(fields)
        if key in seen:
            errors.append(
                f"{path}:{line_number}: duplicate of line {seen[key]}: {','.join(fields)}"
            )
        else:
            seen[key] = line_number
        count += 1

    minimum = MINIMUM_RULE_COUNTS.get(path.name, 1)
    if count < minimum:
        errors.append(f"{path}: expected at least {minimum} rules, found {count}")
    if path.name == "Direct.list":
        rule_bases = {(fields[0], fields[1]) for fields in seen}
        for missing in sorted(STEAM_DIRECT_RULES - rule_bases):
            errors.append(f"{path}: missing Steam DIRECT rule {','.join(missing)}")
        for stale in sorted(STALE_DIRECT_RULES & rule_bases):
            errors.append(f"{path}: stale DIRECT rule remains {','.join(stale)}")
        for non_download in sorted(NON_DOWNLOAD_STEAM_RULES & rule_bases):
            errors.append(
                f"{path}: non-download Steam rule must remain proxied "
                f"{','.join(non_download)}"
            )
    log(f"file={path.name} rules={count} minimum={minimum}")
    return errors


def validate_rules_directory(rules_dir: Path) -> list[str]:
    """Validate every expected published list and reject unknown files."""
    files = sorted(rules_dir.glob("*.list")) if rules_dir.is_dir() else []
    if not files:
        return [f"{rules_dir}: no .list files found"]

    errors: list[str] = []
    actual_names = {path.name for path in files}
    expected_names = set(PUBLISHED_RULE_SETS)
    for missing in sorted(expected_names - actual_names):
        errors.append(f"{rules_dir}: missing published rule set {missing}")
    for unexpected in sorted(actual_names - expected_names):
        errors.append(f"{rules_dir}: unexpected rule set {unexpected}")
    for path in files:
        errors.extend(validate_rule_file(path))
    return errors


def load_published_rules(rules_dir: Path) -> dict[str, set[tuple[str, ...]]]:
    """Load normalized rules keyed by the policy supplied by the profile."""
    rules_by_policy: dict[str, set[tuple[str, ...]]] = {}
    for name, (policy, _) in PUBLISHED_RULE_SETS.items():
        path = rules_dir / name
        if not path.is_file():
            continue
        for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
            fields, error = parse_rule(raw_line, f"{path}:{line_number}")
            if error or fields is None:
                continue
            rules_by_policy.setdefault(policy, set()).add(tuple(fields))
    return rules_by_policy


def validate_surge_config(path: Path, rules_dir: Path) -> list[str]:
    """Check local integration, completed migration, and Apple de-duplication."""
    if not path.is_file():
        return [f"{path}: Surge config not found"]

    lines = path.read_text().splitlines()
    errors: list[str] = []

    custom_ref_indexes: list[int] = []
    for name, (policy, _) in PUBLISHED_RULE_SETS.items():
        url = f"{RAW_BASE_URL}/{name}"
        refs = [(index, line) for index, line in enumerate(lines) if url in line]
        if len(refs) != 1:
            errors.append(
                f"{path}: expected one custom {name} reference, found {len(refs)}"
            )
            continue

        index, raw_line = refs[0]
        custom_ref_indexes.append(index)
        try:
            fields = [field.strip() for field in next(csv.reader([raw_line]))]
        except csv.Error as exc:
            errors.append(f"{path}:{index + 1}: invalid RULE-SET CSV syntax: {exc}")
            continue
        if len(fields) < 3 or fields[0] != "RULE-SET" or fields[2] != policy:
            errors.append(
                f"{path}:{index + 1}: {name} must use policy {policy!r}"
            )
        if "extended-matching" in fields[3:]:
            errors.append(
                f"{path}:{index + 1}: {name} must preserve ordinary inline matching"
            )

    upstream_refs = [
        index
        for index, line in enumerate(lines)
        if "blackmatrix7/ios_rule_script/master/rule/Surge/" in line
    ]
    if custom_ref_indexes and upstream_refs and max(custom_ref_indexes) > upstream_refs[0]:
        errors.append(f"{path}: all custom rule sets must precede upstream rule sets")

    # A published rule must not remain inline, otherwise the two copies can
    # drift. The policy is removed before comparing with the hosted syntax.
    published_rules = load_published_rules(rules_dir)
    remaining_published_rules: list[int] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.split(" //", 1)[0].strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        try:
            fields = [field.strip() for field in next(csv.reader([line]))]
        except csv.Error:
            continue
        if fields[0] == "RULE-SET" or len(fields) < 3:
            continue
        policy = fields[2]
        rule_without_policy = tuple(fields[:2] + fields[3:])
        if rule_without_policy in published_rules.get(policy, set()):
            remaining_published_rules.append(line_number)
    if remaining_published_rules:
        errors.append(
            f"{path}: {len(remaining_published_rules)} published rules remain inline; "
            f"first is line {remaining_published_rules[0]}"
        )

    umbrella_count = sum(APPLE_UMBRELLA in line for line in lines)
    if umbrella_count != 1:
        errors.append(f"{path}: expected one Apple umbrella rule set, found {umbrella_count}")
    for subrule in sorted(APPLE_INCLUDED_SUBRULES):
        if any(subrule in line for line in lines):
            errors.append(f"{path}: redundant Apple subrule remains: {subrule}")

    # Direct download exceptions are evaluated first; every broader upstream
    # Steam match must then use the general proxy policy without a wrapper.
    steam_upstream_refs = [
        (line_number, raw_line)
        for line_number, raw_line in enumerate(lines, start=1)
        if "/rule/Surge/Steam/" in raw_line
        or "/rule/Surge/SteamCN/" in raw_line
    ]
    if len(steam_upstream_refs) != 2:
        errors.append(
            f"{path}: expected two upstream Steam rule sets, "
            f"found {len(steam_upstream_refs)}"
        )
    for line_number, raw_line in steam_upstream_refs:
        fields = [field.strip() for field in next(csv.reader([raw_line]))]
        if len(fields) < 3 or fields[2] != "👻 Proxy":
            errors.append(
                f"{path}:{line_number}: non-download Steam rules must use '👻 Proxy'"
            )

    policy_config = path.with_name("proxy_group.dconf")
    if policy_config.is_file() and "🎮 Steam" in policy_config.read_text():
        errors.append(f"{policy_config}: redundant Steam wrapper group remains")

    log(
        f"config={path} custom_refs={len(custom_ref_indexes)} "
        f"apple_umbrella_refs={umbrella_count}"
    )
    return errors


def validate_mihomo_config(path: Path, rules_dir: Path) -> list[str]:
    """Validate Mihomo text providers without printing sensitive YAML fields."""
    if not path.is_file():
        return [f"{path}: Mihomo config not found"]

    try:
        import yaml
    except ImportError:
        return [f"{path}: PyYAML is required for --mihomo-config validation"]

    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        return [f"{path}: invalid YAML: {exc}"]
    if not isinstance(data, dict):
        return [f"{path}: top-level YAML value must be a mapping"]

    errors: list[str] = []
    providers = data.get("rule-providers") or {}
    if not isinstance(providers, dict):
        return [f"{path}: rule-providers must be a mapping"]

    for filename, (provider_name, _) in MIHOMO_RULE_PROVIDERS.items():
        provider = providers.get(provider_name)
        if not isinstance(provider, dict):
            errors.append(f"{path}: missing Mihomo provider {provider_name}")
            continue

        expected = {
            "type": "http",
            "behavior": "classical",
            "format": "text",
            "path": f"./rule_provider/custom-{filename}",
            "url": f"{RAW_BASE_URL}/{filename}",
            "interval": 86400,
        }
        for key, expected_value in expected.items():
            if provider.get(key) != expected_value:
                errors.append(
                    f"{path}: provider {provider_name} has invalid {key}; "
                    f"expected {expected_value!r}"
                )

    groups = {
        group.get("name"): group
        for group in (data.get("proxy-groups") or [])
        if isinstance(group, dict) and group.get("name")
    }
    uk_group = groups.get("🇬🇧 UK")
    if not isinstance(uk_group, dict):
        errors.append(f"{path}: missing proxy group '🇬🇧 UK'")
    else:
        if uk_group.get("type") != "url-test":
            errors.append(f"{path}: '🇬🇧 UK' must use type 'url-test'")
        if uk_group.get("include-all-providers") is not True:
            errors.append(f"{path}: '🇬🇧 UK' must include all providers")
        if "🇬🇧" not in str(uk_group.get("filter", "")):
            errors.append(f"{path}: '🇬🇧 UK' filter must select UK nodes")

    for group_name in sorted(MIHOMO_GROUPS_WITH_UK):
        group = groups.get(group_name)
        if not isinstance(group, dict) or "🇬🇧 UK" not in (group.get("proxies") or []):
            errors.append(f"{path}: group {group_name!r} must reference '🇬🇧 UK'")
    if "🎯 Direct" in groups:
        errors.append(f"{path}: redundant '🎯 Direct' wrapper group remains")
    if "🎮 Steam" in groups:
        errors.append(f"{path}: redundant '🎮 Steam' wrapper group remains")
    for group_name, group in groups.items():
        if "🎯 Direct" in (group.get("proxies") or []):
            errors.append(f"{path}: group {group_name!r} still references '🎯 Direct'")
        if "🎮 Steam" in (group.get("proxies") or []):
            errors.append(f"{path}: group {group_name!r} still references '🎮 Steam'")
    other_filter = str((groups.get("🌍 Other") or {}).get("filter", ""))
    if "🇬🇧" not in other_filter:
        errors.append(f"{path}: '🌍 Other' must exclude UK nodes")

    rules = data.get("rules") or []
    if not isinstance(rules, list):
        return errors + [f"{path}: rules must be a list"]

    parsed_rules: list[tuple[int, list[str]]] = []
    for index, raw_rule in enumerate(rules):
        if not isinstance(raw_rule, str):
            continue
        try:
            fields = [field.strip() for field in next(csv.reader([raw_rule]))]
        except csv.Error as exc:
            errors.append(f"{path}: rules[{index}] has invalid CSV syntax: {exc}")
            continue
        parsed_rules.append((index, fields))

    direct_wrapper_rules = [
        index
        for index, fields in parsed_rules
        if len(fields) >= 3 and fields[2] == "🎯 Direct"
    ]
    if direct_wrapper_rules:
        errors.append(
            f"{path}: {len(direct_wrapper_rules)} rules still use '🎯 Direct'; "
            f"first is rules[{direct_wrapper_rules[0]}]"
        )

    steam_upstream_refs = [
        (index, fields)
        for index, fields in parsed_rules
        if len(fields) >= 2
        and fields[0] == "RULE-SET"
        and fields[1] in {"steam", "steam_cn"}
    ]
    if len(steam_upstream_refs) != 2:
        errors.append(
            f"{path}: expected two upstream Steam provider references, "
            f"found {len(steam_upstream_refs)}"
        )
    for index, fields in steam_upstream_refs:
        if len(fields) < 3 or fields[2] != "👻 Proxy":
            errors.append(
                f"{path}: rules[{index}] non-download Steam rules must use '👻 Proxy'"
            )

    custom_provider_names = {
        provider_name for provider_name, _ in MIHOMO_RULE_PROVIDERS.values()
    }
    custom_ref_indexes: list[int] = []
    for _, (provider_name, policy) in MIHOMO_RULE_PROVIDERS.items():
        refs = [
            (index, fields)
            for index, fields in parsed_rules
            if len(fields) >= 2
            and fields[0] == "RULE-SET"
            and fields[1] == provider_name
        ]
        if len(refs) != 1:
            errors.append(
                f"{path}: expected one RULE-SET reference for {provider_name}, "
                f"found {len(refs)}"
            )
            continue
        index, fields = refs[0]
        custom_ref_indexes.append(index)
        if len(fields) < 3 or fields[2] != policy:
            errors.append(
                f"{path}: RULE-SET {provider_name} must use policy {policy!r}"
            )

    upstream_ref_indexes = [
        index
        for index, fields in parsed_rules
        if len(fields) >= 2
        and fields[0] == "RULE-SET"
        and fields[1] not in custom_provider_names
    ]
    if (
        custom_ref_indexes
        and upstream_ref_indexes
        and max(custom_ref_indexes) > min(upstream_ref_indexes)
    ):
        errors.append(f"{path}: all custom providers must precede upstream providers")

    # Compare TYPE and VALUE so a stale inline IP rule is caught even if its
    # no-resolve option differs from the canonical published rule.
    published_bases: set[tuple[str, str]] = set()
    for filename in MIHOMO_RULE_PROVIDERS:
        rule_path = rules_dir / filename
        if not rule_path.is_file():
            continue
        for line_number, raw_line in enumerate(rule_path.read_text().splitlines(), start=1):
            fields, error = parse_rule(raw_line, f"{rule_path}:{line_number}")
            if error or fields is None:
                continue
            published_bases.add((fields[0], fields[1]))

    remaining_inline = [
        index
        for index, fields in parsed_rules
        if len(fields) >= 3
        and fields[0] not in {"RULE-SET", "MATCH"}
        and (fields[0], fields[1]) in published_bases
    ]
    if remaining_inline:
        errors.append(
            f"{path}: {len(remaining_inline)} published rules remain inline; "
            f"first is rules[{remaining_inline[0]}]"
        )

    log(
        f"mihomo_config={path} custom_providers={len(custom_ref_indexes)} "
        f"rule_providers={len(providers)}"
    )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "rules",
        help="directory containing published .list files",
    )
    parser.add_argument(
        "--surge-config",
        type=Path,
        help="optional local rule.dconf to validate after migration",
    )
    parser.add_argument(
        "--mihomo-config",
        type=Path,
        help="optional local Mihomo config.yaml to validate after migration",
    )
    args = parser.parse_args()

    errors = validate_rules_directory(args.rules_dir)
    if args.surge_config:
        errors.extend(validate_surge_config(args.surge_config, args.rules_dir))
    if args.mihomo_config:
        errors.extend(validate_mihomo_config(args.mihomo_config, args.rules_dir))

    if errors:
        for error in errors:
            print(f"[validate] ERROR {error}", file=sys.stderr)
        log(f"result=FAIL errors={len(errors)}")
        return 1

    log("result=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
