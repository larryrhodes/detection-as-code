import json
import os
import sys
from wazuh_api import WazuhAPI
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_expected_alert(path):
    with open(path, "r") as f:
        return json.load(f)

def validate_alert(actual_alerts, expected):
    hits = actual_alerts.get("hits", {}).get("hits", [])
    
    if not hits:
        print("❌ FAIL — No alerts found")
        return False

    for hit in hits:
        source = hit.get("_source", {})
        match = True

        # Check agent name
        if "agent" in expected:
            if expected["agent"].get("name") != source.get("agent", {}).get("name"):
                match = False
                continue

        # Check MITRE technique
        if "rule" in expected:
            expected_mitre = expected["rule"].get("mitre", {}).get("id", [])
            actual_mitre = source.get("rule", {}).get("mitre", {}).get("id", [])
            if not any(t in actual_mitre for t in expected_mitre):
                match = False
                continue

        if match:
            print("✅ PASS — Alert matched expected criteria")
            print(f"   Agent:       {source['agent']['name']}")
            print(f"   Rule:        {source['rule']['description']}")
            print(f"   MITRE ID:    {source['rule'].get('mitre', {}).get('id', 'N/A')}")
            print(f"   Timestamp:   {source['timestamp']}")
            return True

    print("❌ FAIL — No alerts matched expected criteria")
    return False


if __name__ == "__main__":
    expected_path = sys.argv[1] if len(sys.argv) > 1 else \
        "atomic-tests/linux/T1059.004/expected_alert.json"

    print(f"📋 Loading expected alert from: {expected_path}")
    expected = load_expected_alert(expected_path)

    api = WazuhAPI()
    api.authenticate()

    print("🔍 Querying Wazuh for recent alerts from emulation-vm...")
    alerts = api.get_alerts("emulation-vm", limit=20)

    print("\n🧪 Validating alerts against expected criteria...")
    result = validate_alert(alerts, expected)

    sys.exit(0 if result else 1)
