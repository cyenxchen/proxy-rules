"""Regression checks for the required Surge matching mode."""

import tempfile
import unittest
from pathlib import Path

from validate_rules import parse_rule, validate_surge_config


class RuleParsingTests(unittest.TestCase):
    def test_accepts_policy_free_domain_wildcard(self):
        fields, error = parse_rule(
            "DOMAIN-WILDCARD,*pcdn*.biliapi.net", "Reject.list:1"
        )
        self.assertIsNone(error)
        self.assertEqual(fields, ["DOMAIN-WILDCARD", "*pcdn*.biliapi.net"])


class SurgeExtendedMatchingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.config = Path(temporary.name) / "rule.dconf"
        self.rules_dir = Path(__file__).resolve().parents[1] / "rules"

    def write_config(self, ordinary_rule_set=None):
        policies = [
            ("Reject", "REJECT"),
            ("Apple", "🍎 Apple"),
            ("Claude", "🔒 ClaudeAI"),
            ("Direct", "DIRECT"),
            ("IndependentIP", "🏠 Independent-IP"),
            ("JP", "🇯🇵 JP"),
            ("PlayStation", "🎮 PlayStation"),
            ("Proxy", "👻 Proxy"),
            ("SGP", "🇸🇬 SGP"),
            ("UK", "🇬🇧 UK"),
            ("US", "🇺🇸 US"),
        ]
        base = "https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules"
        lines = ["[Rule]"]
        for name, policy in policies:
            option = "" if name == ordinary_rule_set else ",extended-matching"
            lines.append(f'RULE-SET,{base}/{name}.list,"{policy}"{option}')
        upstream = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge"
        for name in ("Apple", "Steam", "SteamCN"):
            lines.append(f'RULE-SET,{upstream}/{name}/{name}.list,"👻 Proxy"')
        self.config.write_text("\n".join(lines) + "\n")

    def test_accepts_rule_sets_with_extended_matching(self):
        self.write_config()
        self.assertEqual(validate_surge_config(self.config, self.rules_dir), [])

    def test_rejects_rule_set_without_extended_matching(self):
        self.write_config(ordinary_rule_set="Proxy")
        errors = validate_surge_config(self.config, self.rules_dir)
        self.assertTrue(
            any("Proxy.list" in error and "extended-matching" in error for error in errors),
            errors,
        )

    def test_rejects_reject_list_after_other_custom_rules(self):
        self.write_config()
        lines = self.config.read_text().splitlines()
        reject = lines.pop(1)
        lines.insert(3, reject)
        self.config.write_text("\n".join(lines) + "\n")
        errors = validate_surge_config(self.config, self.rules_dir)
        self.assertTrue(
            any("Reject.list must precede other custom rule sets" in error for error in errors),
            errors,
        )


if __name__ == "__main__":
    unittest.main()
