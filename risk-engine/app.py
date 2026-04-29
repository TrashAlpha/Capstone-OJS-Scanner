from flask import Flask

from flask import request, jsonify

app = Flask(__name__)

from datetime import datetime
import re

class RiskEngine:

    def __init__(self, data):
        self.data = data
        self.target = self._validate_target(data.get('target', 'unknown'))
        self.timestamp = data.get('timestamp') or datetime.now().strftime('%Y-%m-%d')
        self.vulnerabilities = data.get('vulnerabilities', [])
        # Backward compatibility: parse from nuclei/ffuf/internal if vulnerabilities not provided
        if not self.vulnerabilities:
            self.vulnerabilities = self._parse_vulns_from_tools()

    def _validate_target(self, target):
        # Validasi sederhana: domain atau URL
        url_regex = re.compile(r'^(https?://)?([\w.-]+)(:[0-9]+)?(/.*)?$')
        if not target or not url_regex.match(target):
            return 'invalid-target'
        return target

    def _parse_vulns_from_tools(self):
        vulns = []
        nuclei = self.data.get('nuclei', [])
        for n in nuclei:
            vulns.append({
                'name': n.get('name', 'Unknown') if isinstance(n, dict) else str(n),
                'severity': n.get('severity', 'Medium') if isinstance(n, dict) else 'Medium',
                'tool': 'Nuclei',
                'desc': n.get('desc', '') if isinstance(n, dict) else ''
            })
        ffuf = self.data.get('ffuf', [])
        for f in ffuf:
            vulns.append({
                'name': f.get('name', 'Unknown') if isinstance(f, dict) else str(f),
                'severity': f.get('severity', 'Low') if isinstance(f, dict) else 'Low',
                'tool': 'FFUF',
                'desc': f.get('desc', '') if isinstance(f, dict) else ''
            })
        internal = self.data.get('internal', [])
        for i in internal:
            vulns.append({
                'name': i.get('name', 'Unknown') if isinstance(i, dict) else str(i),
                'severity': i.get('severity', 'Medium') if isinstance(i, dict) else 'Medium',
                'tool': 'Internal',
                'desc': i.get('desc', '') if isinstance(i, dict) else ''
            })
        return vulns

    def calculate_final_risk_score(self):
        # Simple scoring: High=5, Medium=3, Low=1
        score = 0
        for v in self.vulnerabilities:
            sev = v.get('severity', '').lower()
            if sev == 'high':
                score += 5
            elif sev == 'medium':
                score += 3
            elif sev == 'low':
                score += 1
            else:
                score += 2
        # Skor rata-rata, dibagi jumlah vuln, max 10
        if self.vulnerabilities:
            final_score = min(round(score / len(self.vulnerabilities), 2), 10)
        else:
            final_score = 0
        return final_score

    def generate_report(self):
        return {
            'target': self.target,
            'timestamp': self.timestamp,
            'vulnerabilities': self.vulnerabilities,
            'final_risk_score': self.calculate_final_risk_score()
        }
@app.route("/")
def home():
    return {"message": "Risk Engine Running"}


# Endpoint untuk menerima data dan mengembalikan hasil risk engine
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    engine = RiskEngine(data)
    report = engine.generate_report()
    return jsonify(report)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
