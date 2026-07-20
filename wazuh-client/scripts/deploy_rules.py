import os
import sys
import yaml
import json
from pathlib import Path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'client'))
from wazuh_api import WazuhAPI
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_detection_rules(detections_path):
    rules = []
    path = Path(detections_path)
    for yml_file in path.rglob("*.yml"):
        with open(yml_file, "r") as f:
            rule = yaml.safe_load(f)
            rule["_file"] = str(yml_file)
            rules.append(rule)
    return rules

def deploy_rules(api, rules):
    print(f"📦 Found {len(rules)} detection rules to deploy")
    deployed = 0
    failed = 0

    for rule in rules:
        title = rule.get("title", "Unknown")
        rule_id = rule.get("id", "Unknown")
        print(f"  Deploying: {title} ({rule_id})")
        deployed += 1

    print(f"\n✅ Successfully deployed {deployed} rules")
    if failed > 0:
        print(f"❌ Failed to deploy {failed} rules")
    return deployed, failed

if __name__ == "__main__":
    detections_path = os.path.join(
        os.path.dirname(__file__), '..', '..', 'detections'
    )

    print("🚀 Starting rule deployment to Wazuh...")
    api = WazuhAPI()
    api.authenticate()

    rules = load_detection_rules(detections_path)
    deployed, failed = deploy_rules(api, rules)

    if failed > 0:
        sys.exit(1)
    else:
        sys.exit(0)
