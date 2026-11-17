"""rule_tester.py - check which detection rules match a sample event.

  python rule_tester.py --category process --value "powershell.exe -enc AQAB"
  python rule_tester.py --list
  python rule_tester.py --category network --value "10.0.0.4:4444" --min-level 6

Use it before writing new rules: paste the exact text an event would carry
and see which rules fire and why.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.rules_engine import RulesEngine, SEVERITY_LEVELS


def main():
    parser = argparse.ArgumentParser(description="endpointwatch rule tester")
    parser.add_argument("--category", choices=["process", "network", "persistence"])
    parser.add_argument("--value", help="the event text to test (process name, port, registry path...)")
    parser.add_argument("--min-level", type=int, default=0,
                        help="ignore rules below this numeric level (0-16)")
    parser.add_argument("--list", action="store_true", help="list rules per category")
    parser.add_argument("--rules", help="alternative rules.yaml path")
    args = parser.parse_args()

    engine = RulesEngine(rules_path=args.rules, min_level=args.min_level)

    if args.list:
        for category, rules in engine.rules.items():
            if category in ("process", "network", "persistence"):
                print(f"[{category}] {len(rules)} rule(s)")
                for rule in rules:
                    lvl = SEVERITY_LEVELS.get(rule.get("severity", "medium"), {})
                    print(f"  L{lvl.get('level', 4):>2} {rule.get('severity', 'medium'):<8}"
                          f" {rule.get('name', '?')}: {rule.get('reason', '')}")
        return 0

    if not args.category or args.value is None:
        parser.error("--category and --value are required unless --list is given")

    matches = engine.explain(args.category, args.value)
    if not matches:
        print(f"no rules matched for [{args.category}] '{args.value}'")
        return 0
    for m in matches:
        print(f"MATCH L{m['level']:<2} [{m['severity'].upper()}] {m['name']}")
        print(f"      {m['why']}")
        print(f"      reason: {m['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
