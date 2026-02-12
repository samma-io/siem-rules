#!/usr/bin/env python3
"""Validate SIEM rules against their test fixtures."""

import json
import os
import re
import sys

import yaml


def resolve_field(data, field_path):
    """Resolve a dot-notation field path against a nested dict."""
    keys = field_path.split(".")
    value = data
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def check_condition(event, condition):
    """Check a single match condition against an event."""
    field = condition["field"]
    value = resolve_field(event, field)
    if value is None:
        return False

    value = str(value)

    if "equals" in condition:
        return value == str(condition["equals"])
    if "regex" in condition:
        return re.search(condition["regex"], value) is not None

    return False


def evaluate_match(event, match_block):
    """Evaluate a match block (and/or) against an event."""
    if "and" in match_block:
        return all(check_condition(event, c) for c in match_block["and"])
    if "or" in match_block:
        return any(check_condition(event, c) for c in match_block["or"])
    return False


def find_test_file(rule_dir, rule_file):
    """Find the matching test fixture for a rule file."""
    category = os.path.basename(rule_dir)
    test_dir = os.path.join("test", category)
    if not os.path.isdir(test_dir):
        return None

    # Look for a JSON file with the same stem or any JSON in the same category
    rule_stem = os.path.splitext(rule_file)[0]
    exact = os.path.join(test_dir, rule_stem + ".json")
    if os.path.isfile(exact):
        return exact

    # Fall back to first JSON file in the test directory
    for f in sorted(os.listdir(test_dir)):
        if f.endswith(".json"):
            return os.path.join(test_dir, f)
    return None


def validate_rule_schema(rule, rule_path):
    """Validate that a rule has all required fields."""
    errors = []
    for field in ("name", "description", "severity", "nats_subject", "match"):
        if field not in rule:
            errors.append(f"  missing required field: {field}")

    if "severity" in rule and rule["severity"] not in ("low", "medium", "high", "critical"):
        errors.append(f"  invalid severity: {rule['severity']}")

    if "match" in rule:
        match = rule["match"]
        if "and" not in match and "or" not in match:
            errors.append("  match block must contain 'and' or 'or'")

    return errors


def main():
    rules_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
    passed = 0
    failed = 0
    errors = []

    for category in sorted(os.listdir(rules_root)):
        category_dir = os.path.join(rules_root, category)
        if not os.path.isdir(category_dir):
            continue

        for rule_file in sorted(os.listdir(category_dir)):
            if not rule_file.endswith((".yaml", ".yml")):
                continue

            rule_path = os.path.join(category_dir, rule_file)
            rel_path = os.path.relpath(rule_path)

            with open(rule_path) as f:
                rule = yaml.safe_load(f)

            # Schema validation
            schema_errors = validate_rule_schema(rule, rule_path)
            if schema_errors:
                failed += 1
                errors.append(f"FAIL {rel_path} (schema)\n" + "\n".join(schema_errors))
                continue

            # Find and run test fixture
            test_file = find_test_file(category_dir, rule_file)
            if test_file is None:
                failed += 1
                errors.append(f"FAIL {rel_path}: no test fixture found")
                continue

            with open(test_file) as f:
                event = json.load(f)

            if evaluate_match(event, rule["match"]):
                passed += 1
                print(f"  PASS {rel_path} <-> {os.path.relpath(test_file)}")
            else:
                failed += 1
                errors.append(
                    f"FAIL {rel_path}: rule did not match test fixture {os.path.relpath(test_file)}"
                )

    print()
    if errors:
        for e in errors:
            print(f"  {e}")
        print()

    total = passed + failed
    print(f"Results: {passed}/{total} passed, {failed} failed")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
