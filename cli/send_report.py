import json
import requests

def send_report(json_path="scan_result.json", url="http://13.61.177.249:8000/register"):
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

if __name__ == "__main__":
    send_report()
