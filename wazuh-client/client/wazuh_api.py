import requests
import json
import os
from dotenv import load_dotenv
import urllib3

# Suppress SSL warnings for self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

class WazuhAPI:
    def __init__(self):
        self.base_url = os.getenv("WAZUH_API_URL")
        self.username = os.getenv("WAZUH_API_USER")
        self.password = os.getenv("WAZUH_API_PASS")
        self.token = None
        self.headers = {"Content-Type": "application/json"}

    def authenticate(self):
        url = f"{self.base_url}/security/user/authenticate"
        response = requests.post(
            url,
            auth=(self.username, self.password),
            verify=False
        )
        data = response.json()
        self.token = data["data"]["token"]
        self.headers["Authorization"] = f"Bearer {self.token}"
        print("✅ Authenticated successfully")
        return self.token

    def get_alerts(self, agent_name, limit=10):
        url = "https://10.211.55.6:9200/wazuh-alerts-*/_search"
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "match": {
                    "agent.name": agent_name
                }
            }
        }
        response = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            auth=("admin", "WazuhAdmin2024-"),
            json=query,
            verify=False
        )
        return response.json()


if __name__ == "__main__":
    api = WazuhAPI()
    api.authenticate()
    print("\n🔍 Fetching recent alerts from emulation-vm...")
    alerts = api.get_alerts("emulation-vm", limit=5)
    print(json.dumps(alerts, indent=2))