#!/usr/bin/env python3
"""
generate_report.py — Detection-as-Code Pipeline Report Generator

Produces JSON and HTML reports from regression run data.
Can also be run standalone to generate a current-state coverage report.

Usage:
  # From a regression summary file:
  python scripts/generate_report.py \
    --input regression_summary.json \
    --output-json reports/regression_20260727.json \
    --output-html reports/regression_20260727.html

  # Standalone coverage report (queries live Wazuh):
  python scripts/generate_report.py --coverage-only
"""

import argparse
import json
import os
import sys
import glob
from datetime import datetime, timezone
from pathlib import Path


# ── Constants ────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).parent.parent
DETECTIONS_DIR = PROJECT_ROOT / "detections" / "linux"
ATOMIC_TESTS_DIR = PROJECT_ROOT / "atomic-tests" / "linux"
REPORTS_DIR = PROJECT_ROOT / "reports"
COVERAGE_MAP = PROJECT_ROOT / "policies" / "mitre_coverage_map.md"


# ── Data Gathering ────────────────────────────────────────────────────────────

def discover_rules() -> list[dict]:
    """Walk detections/linux/ and parse every YAML rule."""
    try:
        import yaml
    except ImportError:
        print("PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    rules = []
    for yml_path in sorted(DETECTIONS_DIR.rglob("*.yml")):
        with open(yml_path) as f:
            try:
                rule = yaml.safe_load(f)
                # Resolve tactic from directory name
                tactic = yml_path.parent.name
                technique_id = yml_path.stem
                atomic_path = ATOMIC_TESTS_DIR / technique_id / "expected_alert.json"

                rules.append({
                    "technique_id": technique_id,
                    "title": rule.get("title", "Unknown"),
                    "tactic": tactic,
                    "level": rule.get("level", "unknown"),
                    "status": rule.get("status", "unknown"),
                    "rule_file": str(yml_path.relative_to(PROJECT_ROOT)),
                    "has_atomic_test": atomic_path.exists(),
                    "tags": rule.get("tags", []),
                    "description": rule.get("description", "").strip(),
                })
            except Exception as e:
                print(f"Warning: Could not parse {yml_path}: {e}", file=sys.stderr)
    return rules


def build_json_report(rules: list[dict], regression: dict | None) -> dict:
    """Assemble the full JSON report payload."""
    now = datetime.now(timezone.utc).isoformat()

    tactics_covered = list({r["tactic"] for r in rules})
    techniques_with_tests = [r for r in rules if r["has_atomic_test"]]

    report = {
        "generated_at": now,
        "pipeline": "Detection-as-Code",
        "repo": "github.com/larryrhodes/detection-as-code",
        "summary": {
            "total_rules": len(rules),
            "tactics_covered": sorted(tactics_covered),
            "tactics_count": len(tactics_covered),
            "rules_with_atomic_tests": len(techniques_with_tests),
            "coverage_percent": round(len(techniques_with_tests) / max(len(rules), 1) * 100, 1),
        },
        "rules": rules,
    }

    if regression:
        report["regression"] = {
            "run_at": regression.get("run_at", now),
            "total": regression.get("total", 0),
            "pass": regression.get("pass", 0),
            "fail": regression.get("fail", 0),
            "pass_rate": round(
                regression.get("pass", 0) / max(regression.get("total", 1), 1) * 100, 1
            ),
            "results": regression.get("results", []),
        }

    # Build ATT&CK Navigator layer
    report["navigator_layer"] = build_navigator_layer(rules, regression)

    return report


def build_navigator_layer(rules: list[dict], regression: dict | None) -> dict:
    """Generate an ATT&CK Navigator JSON layer."""
    regression_results = {}
    if regression:
        for r in regression.get("results", []):
            regression_results[r["technique"]] = r["status"]

    techniques = []
    for rule in rules:
        tech_id = rule["technique_id"].split(".")[0]  # strip sub-technique
        status = regression_results.get(rule["technique_id"], "unknown")

        color = "#4caf50" if status == "pass" else (
            "#f44336" if status == "fail" else "#2196f3"
        )

        techniques.append({
            "techniqueID": tech_id,
            "tactic": rule["tactic"].replace("-", "_"),
            "score": 1,
            "color": color,
            "comment": f"{rule['title']} | Last run: {status}",
            "enabled": True,
        })

    return {
        "name": "Detection-as-Code Coverage",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Auto-generated from detection-as-code pipeline",
        "techniques": techniques,
    }


# ── HTML Generation ───────────────────────────────────────────────────────────

def build_html_report(report: dict) -> str:
    """Render the JSON report as a self-contained HTML page."""
    summary = report["summary"]
    rules = report["rules"]
    regression = report.get("regression")
    generated = report["generated_at"][:10]

    # Regression summary block
    if regression:
        pass_rate = regression["pass_rate"]
        badge_color = "#4caf50" if pass_rate == 100 else (
            "#ff9800" if pass_rate >= 80 else "#f44336"
        )
        regression_html = f"""
        <div class="card" style="border-left: 4px solid {badge_color};">
          <h2>🔍 Regression Run — {regression['run_at'][:10]}</h2>
          <div class="stat-grid">
            <div class="stat"><span class="big">{regression['pass']}</span><br>Passed</div>
            <div class="stat"><span class="big">{regression['fail']}</span><br>Failed</div>
            <div class="stat"><span class="big">{regression['pass_rate']}%</span><br>Pass Rate</div>
          </div>
          <table>
            <thead><tr><th>Technique</th><th>Result</th></tr></thead>
            <tbody>
              {"".join(
                f"<tr><td>{r['technique']}</td>"
                f"<td>{'✅ Pass' if r['status'] == 'pass' else '❌ Fail'}</td></tr>"
                for r in regression['results']
              )}
            </tbody>
          </table>
        </div>
        """
    else:
        regression_html = '<div class="card"><p>No regression data — run the nightly workflow to populate.</p></div>'

    # Rules table rows
    rules_rows = ""
    for r in rules:
        test_badge = "✅" if r["has_atomic_test"] else "⚠️ Missing"
        rules_rows += (
            f"<tr>"
            f"<td><code>{r['technique_id']}</code></td>"
            f"<td>{r['title']}</td>"
            f"<td>{r['tactic']}</td>"
            f"<td>{r['level']}</td>"
            f"<td>{test_badge}</td>"
            f"<td><code>{r['rule_file']}</code></td>"
            f"</tr>\n"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Detection-as-Code Report — {generated}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0d1117; color: #c9d1d9; padding: 2rem; }}
    h1 {{ color: #58a6ff; margin-bottom: 0.25rem; }}
    h2 {{ color: #e6edf3; margin-bottom: 1rem; font-size: 1.1rem; }}
    .subtitle {{ color: #8b949e; margin-bottom: 2rem; font-size: 0.9rem; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
             padding: 1.5rem; margin-bottom: 1.5rem; }}
    .stat-grid {{ display: flex; gap: 2rem; margin-bottom: 1rem; }}
    .stat {{ text-align: center; }}
    .big {{ font-size: 2.5rem; font-weight: bold; color: #58a6ff; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.85rem; }}
    th {{ background: #21262d; color: #8b949e; text-align: left;
          padding: 0.6rem 0.8rem; font-weight: 600; }}
    td {{ padding: 0.6rem 0.8rem; border-top: 1px solid #21262d; }}
    tr:hover td {{ background: #1c2128; }}
    code {{ background: #1c2128; padding: 0.15rem 0.4rem; border-radius: 4px;
            font-family: 'SF Mono', Consolas, monospace; font-size: 0.8rem; color: #79c0ff; }}
    .pill {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 12px;
             font-size: 0.75rem; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>🛡️ Detection-as-Code Pipeline</h1>
  <p class="subtitle">Report generated {generated} · github.com/larryrhodes/detection-as-code</p>

  <div class="card">
    <h2>📊 Coverage Summary</h2>
    <div class="stat-grid">
      <div class="stat"><span class="big">{summary['total_rules']}</span><br>Rules</div>
      <div class="stat"><span class="big">{summary['tactics_count']}</span><br>Tactics</div>
      <div class="stat"><span class="big">{summary['rules_with_atomic_tests']}</span><br>Tested</div>
      <div class="stat"><span class="big">{summary['coverage_percent']}%</span><br>Coverage</div>
    </div>
    <p>Tactics covered: {', '.join(summary['tactics_covered'])}</p>
  </div>

  {regression_html}

  <div class="card">
    <h2>📋 Detection Rules</h2>
    <table>
      <thead>
        <tr>
          <th>Technique</th><th>Title</th><th>Tactic</th>
          <th>Level</th><th>Atomic Test</th><th>File</th>
        </tr>
      </thead>
      <tbody>{rules_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>🗺️ ATT&CK Navigator</h2>
    <p>Import <code>reports/navigator_layer.json</code> at
       <a href="https://mitre-attack.github.io/attack-navigator/" style="color:#58a6ff;">
       mitre-attack.github.io/attack-navigator</a> to view the heatmap.</p>
  </div>
</body>
</html>"""


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Detection-as-Code Report Generator")
    parser.add_argument("--input", help="Regression summary JSON from scheduled-validation.yml")
    parser.add_argument("--output-json", default="reports/report.json", help="JSON output path")
    parser.add_argument("--output-html", default="reports/report.html", help="HTML output path")
    parser.add_argument("--coverage-only", action="store_true", help="Generate coverage report only")
    args = parser.parse_args()

    print("🔍 Discovering detection rules...")
    rules = discover_rules()
    print(f"   Found {len(rules)} rules")

    regression_data = None
    if args.input and not args.coverage_only:
        print(f"📥 Loading regression data from {args.input}...")
        with open(args.input) as f:
            regression_data = json.load(f)

    print("🏗️  Building report...")
    report = build_json_report(rules, regression_data)

    # Write outputs
    REPORTS_DIR.mkdir(exist_ok=True)

    json_path = Path(args.output_json)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"✅ JSON report → {json_path}")

    html_path = Path(args.output_html)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    with open(html_path, "w") as f:
        f.write(build_html_report(report))
    print(f"✅ HTML report → {html_path}")

    # Write ATT&CK Navigator layer separately
    nav_path = REPORTS_DIR / "navigator_layer.json"
    with open(nav_path, "w") as f:
        json.dump(report["navigator_layer"], f, indent=2)
    print(f"✅ Navigator layer → {nav_path}")

    # Print summary
    s = report["summary"]
    print(f"\n📊 Summary: {s['total_rules']} rules · "
          f"{s['tactics_count']} tactics · "
          f"{s['coverage_percent']}% tested")


if __name__ == "__main__":
    main()
