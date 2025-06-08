import json
import requests

def send_report(json_path, url):
    try:
        with open(json_path, "r") as f:
            payload = json.load(f)

        response = requests.post(url, json=payload)
        print(f"[+] Sent report to {url}")
        print(f"    Status: {response.status_code}")
        try:
            print("    Response JSON:", response.json())
        except:
            print("    Response:", response.text)

    except Exception as e:
        print(f"[!] Failed to send report: {e}")

"""
cli/send_report.py
Send a JSON payload (diff or full) to the dashboard API.
"""
def send_report_diff(payload, url):
    """
    POST `payload` (a dict) as JSON to the given URL.
    """
    try:
        resp = requests.post(url, json=payload)
        print(f"[+] Sent payload to {url} (status {resp.status_code})")
    except Exception as e:
        print(f"[!] Failed to send report: {e}")
