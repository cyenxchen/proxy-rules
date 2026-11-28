"""Regression checks for the required Surge matching mode."""

import tempfile
import unittest
from pathlib import Path

from validate_rules import parse_rule, validate_mihomo_config, validate_surge_config


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
            ("Direct", "DIRECT"),
            ("Gemini", "Gemini"),
            ("Proxy", "👻 Proxy"),
            ("Claude", "💎 Selected-IP"),
            ("IndependentIP", "💎 Selected-IP"),
            ("UK", "Other"),
            ("US", "🇺🇸 US"),
            ("JP", "🇯🇵 JP"),
            ("SGP", "🇸🇬 SGP"),
            ("PlayStation", "PlayStation"),
            ("Apple", "Apple"),
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


class MihomoConfigValidationTests(unittest.TestCase):
    def setUp(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML is not installed")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.config = Path(temporary.name) / "config.yaml"
        self.rules_dir = Path(__file__).resolve().parents[1] / "rules"

    def test_accepts_current_mihomo_providers_and_groups(self):
        import yaml

        providers = {}
        rules = []
        mapping = [
            ("Reject.list", "customReject", "REJECT"),
            ("Direct.list", "customDirect", "DIRECT"),
            ("Gemini.list", "Gemini", "Gemini"),
            ("Proxy.list", "customProxy", "👻 Proxy"),
            ("Claude.list", "customClaude", "💎 Selected-IP"),
            ("IndependentIP.list", "customIndependentIP", "💎 Selected-IP"),
            ("UK.list", "customUK", "Other"),
            ("US.list", "customUS", "🇺🇸 US"),
            ("JP.list", "customJP", "🇯🇵 JP"),
            ("SGP.list", "customSGP", "🇸🇬 SGP"),
            ("PlayStation.list", "customPlayStation", "PlayStation"),
            ("Apple.list", "customApple", "Apple"),
        ]
        base = "https://raw.githubusercontent.com/cyenxchen/proxy-rules/main/rules"
        for filename, provider_name, policy in mapping:
            providers[provider_name] = {
                "type": "http",
                "behavior": "classical",
                "format": "text",
                "path": f"./rule_provider/custom-{filename}",
                "url": f"{base}/{filename}",
                "interval": 86400,
            }
            rules.append(f"RULE-SET,{provider_name},{policy}")
        for upstream in ("steam", "steam_cn"):
            providers[upstream] = {"type": "http", "behavior": "classical"}
            rules.append(f"RULE-SET,{upstream},👻 Proxy")
        rules.append("MATCH,REJECT")
        groups = [
            {"name": name, "type": "select", "proxies": ["DIRECT"]}
            for name in (
                "👻 Proxy",
                "💎 Selected-IP",
                "Gemini",
                "Other",
                "🇺🇸 US",
                "🇯🇵 JP",
                "🇸🇬 SGP",
                "PlayStation",
                "Apple",
            )
        ]
        self.config.write_text(
            yaml.safe_dump(
                {"proxy-groups": groups, "rule-providers": providers, "rules": rules},
                allow_unicode=True,
            )
        )
        self.assertEqual(validate_mihomo_config(self.config, self.rules_dir), [])


if __name__ == "__main__":
    unittest.main()
