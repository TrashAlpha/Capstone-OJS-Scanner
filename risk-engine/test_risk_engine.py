import requests

url = "http://localhost:5000/analyze"
data = {
    "target": "ojs-kampus.id",
    "timestamp": "2026-04-17",
    "vulnerabilities": [
        {"name": "XSS", "severity": "High", "tool": "Nuclei", "desc": "Found in search param"},
        {"name": "IDOR", "severity": "Medium", "tool": "Custom-Python", "desc": "Accessing sub_id=99"}
    ]
}

response = requests.post(url, json=data)
print("Status Code:", response.status_code)
print("Response JSON:", response.json())
