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
    "Apple.list": ("🍎 Apple", 4),
    "Direct.list": ("DIRECT", 12),
    "IndependentIP.list": ("🏠 Independent-IP", 18),
    "JP.list": ("🇯🇵 JP", 3),
    "PlayStation.list": ("🎮 PlayStation", 6),
    "Proxy.list": ("👻 Proxy", 376),
    "SGP.list": ("🇸🇬 SGP", 13),
    "UK.list": ("🇬🇧 UK", 2),
    "US.list": ("🇺🇸 US", 8),
}
MINIMUM_RULE_COUNTS = {
    name: minimum for name, (_, minimum) in PUBLISHED_RULE_SETS.items()
}
RAW_BASE_URL = (
    "https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules"
)
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

    log(
        f"config={path} custom_refs={len(custom_ref_indexes)} "
        f"apple_umbrella_refs={umbrella_count}"
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
    args = parser.parse_args()

    errors = validate_rules_directory(args.rules_dir)
    if args.surge_config:
        errors.extend(validate_surge_config(args.surge_config, args.rules_dir))

    if errors:
        for error in errors:
            print(f"[validate] ERROR {error}", file=sys.stderr)
        log(f"result=FAIL errors={len(errors)}")
        return 1

    log("result=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
